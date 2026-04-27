// Encryption support for sensitive Config fields.
//
// Sensitive fields (GoDaddy API key/secret, ACME email) are stored on disk
// with an "enc:" prefix followed by the base64url-encoded AES-256-GCM
// ciphertext produced by the crypto package.  In memory, all fields are
// always plaintext.
//
// The encryption key is read from the PROXYGATE_CONFIG_KEY environment
// variable (64 hex chars = 32 bytes).  If the variable is absent and no
// sensitive fields are encrypted, the manager proceeds without encryption.
// If the variable is absent but encrypted fields are present, load fails.
package config

import (
	"fmt"
	"strings"

	"github.com/gcis/proxygate/internal/crypto"
)

const encPrefix = "enc:"

// IsSensitiveFieldEncrypted reports whether a config field value is encrypted
// (i.e., has the "enc:" prefix).
func IsSensitiveFieldEncrypted(value string) bool {
	return strings.HasPrefix(value, encPrefix)
}

// EncryptSensitiveFields encrypts GoDaddy.APIKey, GoDaddy.APISecret, and
// ACME.Email in place if they are not already encrypted.  Fields that already
// carry the "enc:" prefix are left unchanged (idempotent).
func EncryptSensitiveFields(cfg *Config, key []byte) error {
	var err error
	if cfg.GoDaddy.APIKey != "" && !IsSensitiveFieldEncrypted(cfg.GoDaddy.APIKey) {
		cfg.GoDaddy.APIKey, err = encryptField(key, cfg.GoDaddy.APIKey)
		if err != nil {
			return fmt.Errorf("encrypting GoDaddy.APIKey: %w", err)
		}
	}
	if cfg.GoDaddy.APISecret != "" && !IsSensitiveFieldEncrypted(cfg.GoDaddy.APISecret) {
		cfg.GoDaddy.APISecret, err = encryptField(key, cfg.GoDaddy.APISecret)
		if err != nil {
			return fmt.Errorf("encrypting GoDaddy.APISecret: %w", err)
		}
	}
	if cfg.ACME.Email != "" && !IsSensitiveFieldEncrypted(cfg.ACME.Email) {
		cfg.ACME.Email, err = encryptField(key, cfg.ACME.Email)
		if err != nil {
			return fmt.Errorf("encrypting ACME.Email: %w", err)
		}
	}
	return nil
}

// DecryptSensitiveFields decrypts all "enc:"-prefixed fields in place.
// Fields without the prefix are left unchanged.
func DecryptSensitiveFields(cfg *Config, key []byte) error {
	var err error
	if IsSensitiveFieldEncrypted(cfg.GoDaddy.APIKey) {
		cfg.GoDaddy.APIKey, err = decryptField(key, cfg.GoDaddy.APIKey)
		if err != nil {
			return fmt.Errorf("decrypting GoDaddy.APIKey: %w", err)
		}
	}
	if IsSensitiveFieldEncrypted(cfg.GoDaddy.APISecret) {
		cfg.GoDaddy.APISecret, err = decryptField(key, cfg.GoDaddy.APISecret)
		if err != nil {
			return fmt.Errorf("decrypting GoDaddy.APISecret: %w", err)
		}
	}
	if IsSensitiveFieldEncrypted(cfg.ACME.Email) {
		cfg.ACME.Email, err = decryptField(key, cfg.ACME.Email)
		if err != nil {
			return fmt.Errorf("decrypting ACME.Email: %w", err)
		}
	}
	return nil
}

// hasSensitiveEncryptedFields returns true if any sensitive field carries the
// "enc:" prefix (i.e., the config was previously encrypted).
func hasSensitiveEncryptedFields(cfg *Config) bool {
	return IsSensitiveFieldEncrypted(cfg.GoDaddy.APIKey) ||
		IsSensitiveFieldEncrypted(cfg.GoDaddy.APISecret) ||
		IsSensitiveFieldEncrypted(cfg.ACME.Email)
}

// hasSensitivePlaintextFields returns true if any sensitive field is non-empty
// and does not carry the "enc:" prefix.
func hasSensitivePlaintextFields(cfg *Config) bool {
	return (cfg.GoDaddy.APIKey != "" && !IsSensitiveFieldEncrypted(cfg.GoDaddy.APIKey)) ||
		(cfg.GoDaddy.APISecret != "" && !IsSensitiveFieldEncrypted(cfg.GoDaddy.APISecret)) ||
		(cfg.ACME.Email != "" && !IsSensitiveFieldEncrypted(cfg.ACME.Email))
}

// encryptField prepends "enc:" to the AES-256-GCM ciphertext of value.
func encryptField(key []byte, value string) (string, error) {
	ct, err := crypto.Encrypt(key, value)
	if err != nil {
		return "", err
	}
	return encPrefix + ct, nil
}

// decryptField strips the "enc:" prefix and decrypts the remainder.
func decryptField(key []byte, value string) (string, error) {
	ct := strings.TrimPrefix(value, encPrefix)
	return crypto.Decrypt(key, ct)
}
