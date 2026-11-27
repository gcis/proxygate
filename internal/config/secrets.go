package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gcis/proxygate/internal/crypto"
)

// KeyFileName is the generated encryption key, stored next to the config file.
const KeyFileName = "secret.key"

// SecurityConfig holds the advanced, opt-in hardening settings. All of them
// are read at startup; see docs/security.md.
type SecurityConfig struct {
	AdminTLS           AdminTLSConfig `json:"admin_tls"`
	RequireSecureLogin bool           `json:"require_secure_login"`
	SessionIdleTimeout string         `json:"session_idle_timeout,omitempty"`
	SessionMaxAge      string         `json:"session_max_age,omitempty"`
	// EncryptSecrets defaults to true when omitted.
	EncryptSecrets *bool `json:"encrypt_secrets,omitempty"`
}

// AdminTLSConfig enables HTTPS on the admin listener. With no certificate
// configured, a self-signed one is generated in the data directory.
type AdminTLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}

const (
	defaultSessionIdle = 12 * time.Hour
	defaultSessionMax  = 7 * 24 * time.Hour
)

// EncryptSecretsEnabled reports whether sensitive fields are encrypted on disk.
func (s SecurityConfig) EncryptSecretsEnabled() bool {
	return s.EncryptSecrets == nil || *s.EncryptSecrets
}

// SessionIdle returns the idle timeout, falling back to the default when the
// setting is empty or invalid.
func (s SecurityConfig) SessionIdle() time.Duration {
	return parseDurationOr(s.SessionIdleTimeout, defaultSessionIdle)
}

// SessionMax returns the absolute session lifetime.
func (s SecurityConfig) SessionMax() time.Duration {
	return parseDurationOr(s.SessionMaxAge, defaultSessionMax)
}

func parseDurationOr(v string, def time.Duration) time.Duration {
	if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil && d > 0 {
		return d
	}
	return def
}

// SecretsStatus describes how the sensitive config fields are protected.
type SecretsStatus struct {
	// Mode is "env" (PROXYGATE_CONFIG_KEY), "file" (data/secret.key),
	// "disabled" (encrypt_secrets: false) or "none" (nothing stored yet).
	Mode string `json:"mode"`
	// Error is set when stored secrets could not be decrypted at startup.
	Error string `json:"error,omitempty"`
}

// SecretsStatus reports the current protection of sensitive fields.
func (m *Manager) SecretsStatus() SecretsStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	st := SecretsStatus{Mode: m.keyMode}
	if m.secretsErr != nil {
		st.Error = m.secretsErr.Error()
	}
	if st.Mode == "" {
		if m.config != nil && !m.config.Security.EncryptSecretsEnabled() {
			st.Mode = "disabled"
		} else {
			st.Mode = "none"
		}
	}
	return st
}

func (m *Manager) keyFilePath() string {
	return filepath.Join(filepath.Dir(m.filePath), KeyFileName)
}

// resolveKey returns the encryption key and where it came from. The
// environment variable wins; otherwise data/secret.key is used, and created
// when create is true. A nil key with a nil error means no key exists yet.
func (m *Manager) resolveKey(create bool) ([]byte, string, error) {
	if strings.TrimSpace(os.Getenv("PROXYGATE_CONFIG_KEY")) != "" {
		key, err := crypto.KeyFromEnv()
		return key, "env", err
	}

	path := m.keyFilePath()
	data, err := os.ReadFile(path)
	if err == nil {
		key, err := crypto.ParseKey(strings.TrimSpace(string(data)))
		if err != nil {
			return nil, "file", fmt.Errorf("%s: %w", path, err)
		}
		return key, "file", nil
	}
	if !os.IsNotExist(err) {
		return nil, "file", fmt.Errorf("reading %s: %w", path, err)
	}
	if !create {
		return nil, "", nil
	}

	key, err := crypto.NewKey()
	if err != nil {
		return nil, "file", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, "file", err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return m.resolveKey(false) // another writer created it first
		}
		return nil, "file", fmt.Errorf("creating %s: %w", path, err)
	}
	defer f.Close()
	if _, err := f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		return nil, "file", fmt.Errorf("writing %s: %w", path, err)
	}
	return key, "file", nil
}

// sensitiveFields returns pointers to every field that is encrypted at rest.
func sensitiveFields(cfg *Config) map[string]*string {
	return map[string]*string{
		"godaddy.api_key":    &cfg.GoDaddy.APIKey,
		"godaddy.api_secret": &cfg.GoDaddy.APISecret,
		"acme.email":         &cfg.ACME.Email,
	}
}

// decryptLoaded decrypts encrypted fields in cfg one by one. Fields that
// cannot be decrypted are cleared in memory and their ciphertext is stashed
// so a later save writes it back unchanged. The proxy keeps running either
// way: losing the key costs the GoDaddy credentials, not the websites.
func (m *Manager) decryptLoaded(cfg *Config) {
	m.stash = nil
	m.secretsErr = nil
	if !hasSensitiveEncryptedFields(cfg) {
		return
	}

	key, mode, err := m.resolveKey(false)
	if err == nil && key == nil {
		err = fmt.Errorf("config has encrypted fields but no key: set PROXYGATE_CONFIG_KEY or restore %s", m.keyFilePath())
	}
	m.keyMode = mode

	for name, field := range sensitiveFields(cfg) {
		if !IsSensitiveFieldEncrypted(*field) {
			continue
		}
		var plain string
		ferr := err
		if ferr == nil {
			plain, ferr = decryptField(key, *field)
		}
		if ferr != nil {
			if m.stash == nil {
				m.stash = map[string]string{}
			}
			m.stash[name] = *field
			*field = ""
			if m.secretsErr == nil {
				m.secretsErr = fmt.Errorf("could not decrypt %s: %w", name, ferr)
			}
			continue
		}
		*field = plain
	}
}

// encryptForDisk encrypts plaintext sensitive fields in diskCfg (a copy of
// the in-memory config) and restores stashed ciphertext for fields the user
// has not re-entered.
func (m *Manager) encryptForDisk(diskCfg *Config) error {
	if diskCfg.Security.EncryptSecretsEnabled() && hasSensitivePlaintextFields(diskCfg) {
		key, mode, err := m.resolveKey(true)
		if err != nil {
			return fmt.Errorf("cannot encrypt secrets: %w", err)
		}
		if err := EncryptSensitiveFields(diskCfg, key); err != nil {
			return fmt.Errorf("encrypting config for save: %w", err)
		}
		m.keyMode = mode
	}
	for name, field := range sensitiveFields(diskCfg) {
		if *field == "" {
			if enc, ok := m.stash[name]; ok {
				*field = enc
			}
		}
	}
	return nil
}
