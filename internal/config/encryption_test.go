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

// A missing key must not stop ProxyGate: the proxy keeps serving, secrets are
// treated as empty, and their ciphertext survives later saves.
func TestMissingKey_StartsWithSecretsClearedAndPreserved(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	plainCfg := config.DefaultConfig()
	plainCfg.GoDaddy.APIKey = "some-key"
	plainCfg.GoDaddy.APISecret = "some-secret"
	plainCfg.ACME.Email = "user@example.com"
	plainCfg.Routes = []config.ProxyRoute{{ID: "r1", Domain: "a.example.com", TargetHost: "h", TargetPort: 1, Enabled: true}}
	if err := config.EncryptSensitiveFields(plainCfg, testKey()); err != nil {
		t.Fatalf("setup encrypt: %v", err)
	}
	encryptedSecret := plainCfg.GoDaddy.APISecret
	data, _ := json.MarshalIndent(plainCfg, "", "  ")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("PROXYGATE_CONFIG_KEY", "") // no env key and no secret.key file

	m, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager must succeed without the key, got: %v", err)
	}
	cfg := m.Get()
	if cfg.GoDaddy.APIKey != "" || cfg.GoDaddy.APISecret != "" || cfg.ACME.Email != "" {
		t.Errorf("undecryptable secrets must be empty in memory, got %+v %+v", cfg.GoDaddy, cfg.ACME.Email)
	}
	if len(cfg.Routes) != 1 {
		t.Errorf("routes must still load, got %d", len(cfg.Routes))
	}
	if st := m.SecretsStatus(); st.Error == "" || !strings.Contains(st.Error, "PROXYGATE_CONFIG_KEY") {
		t.Errorf("status must explain the missing key, got %+v", st)
	}

	// An unrelated change must not destroy the stored ciphertext.
	if err := m.Update(func(c *config.Config) { c.Server.HTTPPort = 8081 }); err != nil {
		t.Fatalf("Update: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), encryptedSecret) {
		t.Error("stashed ciphertext was not written back on save")
	}
}

// ─── TestTamperedFieldRejected ────────────────────────────────────────────────

func TestTamperedField_ClearedWithError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")

	key := testKey()
	t.Setenv("PROXYGATE_CONFIG_KEY", encodeTestKey(key))

	good := config.DefaultConfig()
	good.ACME.Email = "ok@example.com"
	if err := config.EncryptSensitiveFields(good, key); err != nil {
		t.Fatal(err)
	}
	good.GoDaddy.APIKey = "enc:this-is-not-valid-ciphertext"
	data, _ := json.MarshalIndent(good, "", "  ")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("write: %v", err)
	}

	m, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	cfg := m.Get()
	if cfg.GoDaddy.APIKey != "" {
		t.Errorf("tampered field must be cleared, got %q", cfg.GoDaddy.APIKey)
	}
	if cfg.ACME.Email != "ok@example.com" {
		t.Errorf("valid fields must still decrypt, got %q", cfg.ACME.Email)
	}
	if m.SecretsStatus().Error == "" {
		t.Error("status must report the decryption failure")
	}
}

// Without PROXYGATE_CONFIG_KEY a key file is generated and secrets are
// encrypted on disk by default.
func TestDefaultEncryption_UsesGeneratedKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("PROXYGATE_CONFIG_KEY", "")

	m, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Update(func(c *config.Config) { c.GoDaddy.APISecret = "top-secret" }); err != nil {
		t.Fatal(err)
	}

	raw, _ := os.ReadFile(path)
	if strings.Contains(string(raw), "top-secret") {
		t.Fatal("secret written in plaintext")
	}
	info, err := os.Stat(filepath.Join(dir, config.KeyFileName))
	if err != nil {
		t.Fatalf("key file not created: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Errorf("key file mode: want 0600, got %v", info.Mode().Perm())
	}
	if st := m.SecretsStatus(); st.Mode != "file" || st.Error != "" {
		t.Errorf("status: %+v", st)
	}

	// A fresh manager reads it back with the same key file.
	m2, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := m2.Get().GoDaddy.APISecret; got != "top-secret" {
		t.Errorf("round trip: got %q", got)
	}
}

func TestEncryptSecretsDisabled_WritesPlaintext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	t.Setenv("PROXYGATE_CONFIG_KEY", "")

	m, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if err := m.Update(func(c *config.Config) {
		c.Security.EncryptSecrets = &off
		c.GoDaddy.APISecret = "visible"
	}); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	if !strings.Contains(string(raw), `"visible"`) {
		t.Error("encrypt_secrets=false must store plaintext")
	}
	if _, err := os.Stat(filepath.Join(dir, config.KeyFileName)); !os.IsNotExist(err) {
		t.Error("no key file should be created when encryption is disabled")
	}
	if st := m.SecretsStatus(); st.Mode != "disabled" {
		t.Errorf("status mode: %+v", st)
	}
}

func TestSecurityDurations_DefaultAndOverride(t *testing.T) {
	var s config.SecurityConfig
	if s.SessionIdle().Hours() != 12 || s.SessionMax().Hours() != 168 {
		t.Errorf("defaults: %v %v", s.SessionIdle(), s.SessionMax())
	}
	s.SessionIdleTimeout, s.SessionMaxAge = "2h", "nonsense"
	if s.SessionIdle().Hours() != 2 || s.SessionMax().Hours() != 168 {
		t.Errorf("override/fallback: %v %v", s.SessionIdle(), s.SessionMax())
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
