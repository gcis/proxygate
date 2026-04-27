// Tests for config field encryption/decryption and migration.
package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/config"
)

// testKey returns a deterministic 32-byte key for tests.
func testKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return key
}

// ─── TestEncryptSensitiveFields ───────────────────────────────────────────────

func TestEncryptSensitiveFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GoDaddy.APIKey = "your-godaddy-api-key"
	cfg.GoDaddy.APISecret = "your-godaddy-api-secret"
	cfg.ACME.Email = "user@example.com"

	key := testKey()
	if err := config.EncryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("EncryptSensitiveFields: %v", err)
	}

	// All three fields should now have the "enc:" prefix
	if !strings.HasPrefix(cfg.GoDaddy.APIKey, "enc:") {
		t.Errorf("APIKey should be encrypted, got %q", cfg.GoDaddy.APIKey)
	}
	if !strings.HasPrefix(cfg.GoDaddy.APISecret, "enc:") {
		t.Errorf("APISecret should be encrypted, got %q", cfg.GoDaddy.APISecret)
	}
	if !strings.HasPrefix(cfg.ACME.Email, "enc:") {
		t.Errorf("ACME.Email should be encrypted, got %q", cfg.ACME.Email)
	}

	// They should not equal the original plaintext
	if cfg.GoDaddy.APIKey == "your-godaddy-api-key" {
		t.Error("APIKey was not encrypted")
	}
	if cfg.GoDaddy.APISecret == "your-godaddy-api-secret" {
		t.Error("APISecret was not encrypted")
	}
	if cfg.ACME.Email == "user@example.com" {
		t.Error("ACME.Email was not encrypted")
	}
}

// ─── TestDecryptSensitiveFields ───────────────────────────────────────────────

func TestDecryptSensitiveFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GoDaddy.APIKey = "my-api-key"
	cfg.GoDaddy.APISecret = "my-api-secret"
	cfg.ACME.Email = "user@example.com"

	key := testKey()

	// Encrypt then decrypt
	if err := config.EncryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("EncryptSensitiveFields: %v", err)
	}
	if err := config.DecryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("DecryptSensitiveFields: %v", err)
	}

	if cfg.GoDaddy.APIKey != "my-api-key" {
		t.Errorf("APIKey: want my-api-key, got %q", cfg.GoDaddy.APIKey)
	}
	if cfg.GoDaddy.APISecret != "my-api-secret" {
		t.Errorf("APISecret: want my-api-secret, got %q", cfg.GoDaddy.APISecret)
	}
	if cfg.ACME.Email != "user@example.com" {
		t.Errorf("ACME.Email: want user@example.com, got %q", cfg.ACME.Email)
	}
}

// ─── TestMigrateFromPlaintext ─────────────────────────────────────────────────

func TestMigrateFromPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write a config file with plaintext sensitive fields
	plainCfg := config.DefaultConfig()
	plainCfg.GoDaddy.APIKey = "plaintext-key"
	plainCfg.GoDaddy.APISecret = "plaintext-secret"
	plainCfg.ACME.Email = "admin@example.com"

	data, err := json.MarshalIndent(plainCfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Set encryption key in env
	key := testKey()
	t.Setenv("PROXYGATE_CONFIG_KEY", encodeTestKey(key))

	// Load the manager — it should migrate plaintext to encrypted on disk
	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	// In-memory config should have plaintext values
	cfg := mgr.Get()
	if cfg.GoDaddy.APIKey != "plaintext-key" {
		t.Errorf("in-memory APIKey: want plaintext-key, got %q", cfg.GoDaddy.APIKey)
	}
	if cfg.GoDaddy.APISecret != "plaintext-secret" {
		t.Errorf("in-memory APISecret: want plaintext-secret, got %q", cfg.GoDaddy.APISecret)
	}
	if cfg.ACME.Email != "admin@example.com" {
		t.Errorf("in-memory ACME.Email: want admin@example.com, got %q", cfg.ACME.Email)
	}

	// On-disk config should now have encrypted values
	diskData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read disk: %v", err)
	}
	var diskCfg config.Config
	if err := json.Unmarshal(diskData, &diskCfg); err != nil {
		t.Fatalf("unmarshal disk: %v", err)
	}

	if !strings.HasPrefix(diskCfg.GoDaddy.APIKey, "enc:") {
		t.Errorf("on-disk APIKey should be encrypted, got %q", diskCfg.GoDaddy.APIKey)
	}
	if !strings.HasPrefix(diskCfg.GoDaddy.APISecret, "enc:") {
		t.Errorf("on-disk APISecret should be encrypted, got %q", diskCfg.GoDaddy.APISecret)
	}
	if !strings.HasPrefix(diskCfg.ACME.Email, "enc:") {
		t.Errorf("on-disk ACME.Email should be encrypted, got %q", diskCfg.ACME.Email)
	}
}

// ─── TestAlreadyEncryptedIsIdempotent ─────────────────────────────────────────

func TestAlreadyEncryptedIsIdempotent(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GoDaddy.APIKey = "my-key"
	cfg.GoDaddy.APISecret = "my-secret"
	cfg.ACME.Email = "user@example.com"

	key := testKey()

	// First encryption
	if err := config.EncryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("first EncryptSensitiveFields: %v", err)
	}
	firstKey := cfg.GoDaddy.APIKey
	firstSecret := cfg.GoDaddy.APISecret
	firstEmail := cfg.ACME.Email

	// Second encryption on already-encrypted fields should be idempotent
	if err := config.EncryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("second EncryptSensitiveFields: %v", err)
	}

	// The ciphertext values must not have changed (no double-encrypt)
	if cfg.GoDaddy.APIKey != firstKey {
		t.Error("APIKey was double-encrypted")
	}
	if cfg.GoDaddy.APISecret != firstSecret {
		t.Error("APISecret was double-encrypted")
	}
	if cfg.ACME.Email != firstEmail {
		t.Error("ACME.Email was double-encrypted")
	}

	// Decrypting should still produce original plaintext
	if err := config.DecryptSensitiveFields(cfg, key); err != nil {
		t.Fatalf("DecryptSensitiveFields: %v", err)
	}
	if cfg.GoDaddy.APIKey != "my-key" {
		t.Errorf("after decrypt: APIKey want my-key, got %q", cfg.GoDaddy.APIKey)
	}
}

// ─── TestMissingKeyReturnsError ───────────────────────────────────────────────

func TestMissingKeyReturnsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	// Write config with already-encrypted fields (simulate existing encrypted config)
	plainCfg := config.DefaultConfig()
	plainCfg.GoDaddy.APIKey = "some-key"
	plainCfg.GoDaddy.APISecret = "some-secret"
	plainCfg.ACME.Email = "user@example.com"

	// Encrypt it first with a key
	key := testKey()
	if err := config.EncryptSensitiveFields(plainCfg, key); err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}

	data, err := json.MarshalIndent(plainCfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Ensure env var is not set
	os.Unsetenv("PROXYGATE_CONFIG_KEY") //nolint:errcheck

	// Loading should fail with a clear error because fields are encrypted but no key available
	_, err = config.NewManager(path)
	if err == nil {
		t.Fatal("expected error when loading encrypted config without key, got nil")
	}
	// Error should be descriptive
	if !strings.Contains(err.Error(), "PROXYGATE_CONFIG_KEY") &&
		!strings.Contains(strings.ToLower(err.Error()), "key") {
		t.Errorf("error should mention missing key, got: %v", err)
	}
}

// ─── TestTamperedFieldRejected ────────────────────────────────────────────────

func TestTamperedFieldRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	key := testKey()
	t.Setenv("PROXYGATE_CONFIG_KEY", encodeTestKey(key))

	// Write config with a tampered "enc:" field
	tampered := config.DefaultConfig()
	tampered.GoDaddy.APIKey = "enc:this-is-not-valid-ciphertext"
	tampered.GoDaddy.APISecret = "enc:also-invalid"
	tampered.ACME.Email = "enc:bad"

	data, err := json.MarshalIndent(tampered, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err = config.NewManager(path)
	if err == nil {
		t.Fatal("expected error loading config with tampered ciphertext, got nil")
	}
}

// ─── TestIsSensitiveFieldEncrypted ────────────────────────────────────────────

func TestIsSensitiveFieldEncrypted(t *testing.T) {
	if !config.IsSensitiveFieldEncrypted("enc:somebase64data") {
		t.Error("should return true for enc: prefixed value")
	}
	if config.IsSensitiveFieldEncrypted("plaintext") {
		t.Error("should return false for plain value")
	}
	if config.IsSensitiveFieldEncrypted("") {
		t.Error("should return false for empty string")
	}
	if config.IsSensitiveFieldEncrypted("enc") {
		t.Error("should return false for 'enc' without colon")
	}
}

// encodeTestKey returns the test key as a hex string suitable for the env var.
func encodeTestKey(key []byte) string {
	const hextable = "0123456789abcdef"
	buf := make([]byte, len(key)*2)
	for i, b := range key {
		buf[i*2] = hextable[b>>4]
		buf[i*2+1] = hextable[b&0x0f]
	}
	return string(buf)
}
