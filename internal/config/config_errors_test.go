package config_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/config"
)

func TestDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PROXYGATE_CONFIG_KEY", "")
	m, err := config.NewManager(filepath.Join(dir, "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	if m.Dir() != dir {
		t.Errorf("Dir: %q", m.Dir())
	}
}

func TestWriteFailuresAreReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	t.Setenv("PROXYGATE_CONFIG_KEY", "")
	dir := t.TempDir()
	m, err := config.NewManager(filepath.Join(dir, "p.json"))
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0500)
	defer os.Chmod(dir, 0700) //nolint:errcheck
	if err := m.Update(func(c *config.Config) { c.Server.HTTPPort = 1 }); err == nil {
		t.Error("save into a read-only dir must fail")
	}

	file := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(file, nil, 0600)
	if _, err := config.NewManager(filepath.Join(file, "sub", "p.json")); err == nil {
		t.Error("config under a regular file must fail")
	}
}

func TestInvalidEnvKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	t.Setenv("PROXYGATE_CONFIG_KEY", "not-hex")
	m, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("an invalid key must not stop loading an empty config: %v", err)
	}
	err = m.Update(func(c *config.Config) { c.GoDaddy.APISecret = "s" })
	if err == nil || !strings.Contains(err.Error(), "cannot encrypt secrets") {
		t.Errorf("storing a secret with an invalid key must fail: %v", err)
	}
}

func TestCorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.json")
	t.Setenv("PROXYGATE_CONFIG_KEY", "")
	m, _ := config.NewManager(path)
	_ = m.Update(func(c *config.Config) { c.GoDaddy.APISecret = "s" })

	_ = os.WriteFile(filepath.Join(dir, config.KeyFileName), []byte("garbage"), 0600)
	m2, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if st := m2.SecretsStatus(); st.Error == "" || m2.Get().GoDaddy.APISecret != "" {
		t.Errorf("corrupt key file must be reported and secrets cleared: %+v", st)
	}

	// An unreadable key path (a directory) is also reported.
	_ = os.Remove(filepath.Join(dir, config.KeyFileName))
	_ = os.Mkdir(filepath.Join(dir, config.KeyFileName), 0700)
	m3, _ := config.NewManager(path)
	if m3.SecretsStatus().Error == "" {
		t.Error("unreadable key path must be reported")
	}
}

func TestEncryptDecryptFieldsWithBadKey(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.GoDaddy.APIKey, cfg.GoDaddy.APISecret, cfg.ACME.Email = "k", "s", "e@x.io"
	if err := config.EncryptSensitiveFields(cfg, []byte("short")); err == nil {
		t.Error("encrypting with an invalid key must fail")
	}
	good, _ := hex.DecodeString(strings.Repeat("ab", 32))
	for _, field := range []string{"key", "secret", "email"} {
		c := config.DefaultConfig()
		switch field {
		case "key":
			c.GoDaddy.APIKey = "enc:bad"
		case "secret":
			c.GoDaddy.APISecret = "enc:bad"
		case "email":
			c.ACME.Email = "enc:bad"
		}
		if err := config.DecryptSensitiveFields(c, good); err == nil {
			t.Errorf("decrypting garbage %s must fail", field)
		}
	}
	for _, field := range []string{"secret", "email"} {
		c := config.DefaultConfig()
		if field == "secret" {
			c.GoDaddy.APISecret = "s"
		} else {
			c.ACME.Email = "e"
		}
		if err := config.EncryptSensitiveFields(c, []byte("short")); err == nil {
			t.Errorf("encrypting %s with a bad key must fail", field)
		}
	}
}
