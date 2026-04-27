// Package config manages ProxyGate configuration with file-based persistence and hot reload.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gcis/proxygate/internal/crypto"
)

type ProxyRoute struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	// PathPrefix, when non-empty, only matches requests whose URL path starts
	// with this value.  More-specific (longer) prefixes win over shorter ones.
	// An empty PathPrefix matches all paths for the domain (catch-all).
	PathPrefix  string `json:"path_prefix,omitempty"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
	TLSEnabled  bool   `json:"tls_enabled"`
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
	AutoCert    bool   `json:"auto_cert"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type GoDaddyConfig struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
	BaseURL   string `json:"base_url"`
}

type ACMEConfig struct {
	Email      string `json:"email"`
	Directory  string `json:"directory"`
	CertDir    string `json:"cert_dir"`
	UseStaging bool   `json:"use_staging"`
}

type ServerConfig struct {
	HTTPPort        int      `json:"http_port"`
	HTTPSPort       int      `json:"https_port"`
	AdminPort       int      `json:"admin_port"`
	AdminHost       string   `json:"admin_host"`
	AllowedNetworks []string `json:"allowed_networks"`
}

type Config struct {
	Server  ServerConfig  `json:"server"`
	Routes  []ProxyRoute  `json:"routes"`
	GoDaddy GoDaddyConfig `json:"godaddy"`
	ACME    ACMEConfig    `json:"acme"`
}

type Manager struct {
	mu        sync.RWMutex
	config    *Config
	filePath  string
	listeners []func(*Config)
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:  8080,
			HTTPSPort: 8443,
			AdminPort:       9090,
			AdminHost:       "127.0.0.1",
			AllowedNetworks: []string{"127.0.0.0/8", "::1/128"},
		},
		Routes: []ProxyRoute{},
		GoDaddy: GoDaddyConfig{
			BaseURL: "https://api.godaddy.com",
		},
		ACME: ACMEConfig{
			Directory:  "https://acme-v02.api.letsencrypt.org/directory",
			CertDir:    "./certs",
			UseStaging: true,
		},
	}
}

func NewManager(filePath string) (*Manager, error) {
	m := &Manager{
		filePath: filePath,
	}

	if err := m.load(); err != nil {
		if os.IsNotExist(err) {
			m.config = DefaultConfig()
			if err := m.save(); err != nil {
				return nil, fmt.Errorf("creating default config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("loading config: %w", err)
		}
	}

	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// Handle encryption boundary:
	//   1. If any sensitive field is encrypted, we MUST have a key to decrypt.
	//   2. If any sensitive field is plaintext (and key is available), migrate to encrypted on disk.
	//   3. In memory, all fields are always plaintext after load.
	if hasSensitiveEncryptedFields(cfg) {
		key, err := crypto.KeyFromEnv()
		if err != nil {
			return fmt.Errorf("config contains encrypted fields but no key available — "+
				"set PROXYGATE_CONFIG_KEY: %w", err)
		}
		if err := DecryptSensitiveFields(cfg, key); err != nil {
			return fmt.Errorf("decrypting config fields: %w", err)
		}
	} else if hasSensitivePlaintextFields(cfg) {
		// Try to migrate: if a key is available, encrypt and write back
		key, err := crypto.KeyFromEnv()
		if err == nil {
			// Key available — encrypt plaintext fields and persist
			diskCfg := *cfg // shallow copy for disk write
			if err := EncryptSensitiveFields(&diskCfg, key); err != nil {
				return fmt.Errorf("migrating config encryption: %w", err)
			}
			// Write encrypted version back to disk
			if wErr := m.writeConfig(&diskCfg); wErr != nil {
				// Non-fatal: log would be ideal but Manager has no logger; proceed with plaintext
				_ = wErr
			}
		}
		// Regardless, in-memory config stays plaintext
	}

	m.config = cfg
	return nil
}

func (m *Manager) save() error {
	// Build the version to write to disk.
	// If a key is available, encrypt sensitive fields before persisting.
	diskCfg := *m.config
	diskCfg.Routes = make([]ProxyRoute, len(m.config.Routes))
	copy(diskCfg.Routes, m.config.Routes)

	if key, err := crypto.KeyFromEnv(); err == nil {
		if err := EncryptSensitiveFields(&diskCfg, key); err != nil {
			return fmt.Errorf("encrypting config for save: %w", err)
		}
	}
	// If no key is set, write plaintext (backward compatible).

	return m.writeConfig(&diskCfg)
}

// writeConfig serialises cfg atomically to m.filePath via a tmp-rename.
func (m *Manager) writeConfig(cfg *Config) error {
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	tmpFile := m.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	if err := os.Rename(tmpFile, m.filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("renaming config: %w", err)
	}

	return nil
}

func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cp := *m.config
	cp.Routes = make([]ProxyRoute, len(m.config.Routes))
	copy(cp.Routes, m.config.Routes)
	return &cp
}

func (m *Manager) Update(fn func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	fn(m.config)

	if err := m.save(); err != nil {
		return err
	}

	cfg := *m.config
	for _, listener := range m.listeners {
		listener(&cfg)
	}

	return nil
}

func (m *Manager) OnChange(fn func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *Manager) AddRoute(route ProxyRoute) error {
	return m.Update(func(cfg *Config) {
		now := time.Now().UTC().Format(time.RFC3339)
		route.CreatedAt = now
		route.UpdatedAt = now
		if route.ID == "" {
			route.ID = fmt.Sprintf("route_%d", time.Now().UnixNano())
		}
		cfg.Routes = append(cfg.Routes, route)
	})
}

func (m *Manager) UpdateRoute(id string, updated ProxyRoute) error {
	return m.Update(func(cfg *Config) {
		for i, r := range cfg.Routes {
			if r.ID == id {
				updated.ID = id
				updated.CreatedAt = r.CreatedAt
				updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				cfg.Routes[i] = updated
				return
			}
		}
	})
}

func (m *Manager) DeleteRoute(id string) error {
	return m.Update(func(cfg *Config) {
		for i, r := range cfg.Routes {
			if r.ID == id {
				cfg.Routes = append(cfg.Routes[:i], cfg.Routes[i+1:]...)
				return
			}
		}
	})
}

func (m *Manager) GetRoute(id string) *ProxyRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.config.Routes {
		if r.ID == id {
			cp := r
			return &cp
		}
	}
	return nil
}

func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.load(); err != nil {
		return err
	}

	cfg := *m.config
	for _, listener := range m.listeners {
		listener(&cfg)
	}

	return nil
}
