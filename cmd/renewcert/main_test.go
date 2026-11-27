package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/acmetest"
	"github.com/gcis/proxygate/internal/config"
)

// setup writes a config pointing at a fake ACME CA and a fake GoDaddy API
// (which accepts record writes unless failDNS is set).
func setup(t *testing.T, directory string, failDNS bool) (cfgPath, certDir string) {
	t.Helper()
	gd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failDNS {
			http.Error(w, `{"message":"denied"}`, http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(gd.Close)

	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.ACME.Directory = directory
	cfg.ACME.CertDir = filepath.Join(dir, "certs")
	cfg.GoDaddy = config.GoDaddyConfig{APIKey: "k", APISecret: "s", BaseURL: gd.URL}
	off := false
	cfg.Security.EncryptSecrets = &off
	data, _ := json.Marshal(cfg)
	cfgPath = filepath.Join(dir, "proxygate.json")
	if err := os.WriteFile(cfgPath, data, 0640); err != nil {
		t.Fatal(err)
	}
	return cfgPath, cfg.ACME.CertDir
}

func runRenew(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRenewSucceeds(t *testing.T) {
	ca := acmetest.New()
	defer ca.Close()
	cfgPath, certDir := setup(t, ca.DirectoryURL(), false)

	code, out, _ := runRenew("-config", cfgPath, "-propagation-wait", "0s", "a.example.com", "b.example.com")
	if code != 0 || strings.Count(out, "renewal succeeded") != 2 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, d := range []string{"a.example.com", "b.example.com"} {
		if _, err := os.Stat(filepath.Join(certDir, d+".pem")); err != nil {
			t.Errorf("%s: certificate not written: %v", d, err)
		}
	}
}

func TestRenewFailures(t *testing.T) {
	ca := acmetest.New()
	defer ca.Close()

	cfgPath, _ := setup(t, ca.DirectoryURL(), true)
	if code, out, _ := runRenew("-config", cfgPath, "-propagation-wait", "0s", "a.example.com"); code != 1 || !strings.Contains(out, "creating TXT record") {
		t.Errorf("DNS failure: %d %s", code, out)
	}

	cfgPath, _ = setup(t, ca.DirectoryURL(), false)
	ca.FailValidation.Store(true)
	if code, out, _ := runRenew("-config", cfgPath, "-propagation-wait", "0s", "a.example.com"); code != 1 || !strings.Contains(out, "renewal failed") {
		t.Errorf("validation failure: %d %s", code, out)
	}
	ca.FailValidation.Store(false)

	// An empty domain is rejected by the CA when the order is created.
	if code, out, _ := runRenew("-config", cfgPath, "-propagation-wait", "0s", ""); code != 1 || !strings.Contains(out, "acme request") {
		t.Errorf("rejected order: %d %s", code, out)
	}

	cfgPath, _ = setup(t, "http://127.0.0.1:1/directory", false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	if code := run(ctx, []string{"-config", cfgPath, "a.example.com"}, &out, &bytes.Buffer{}); code != 1 || !strings.Contains(out.String(), "acme register failed") {
		t.Errorf("unreachable CA: %d %s", code, out.String())
	}
}

func TestRenewUsageAndConfigErrors(t *testing.T) {
	if code, _, errOut := runRenew(); code != 2 || !strings.Contains(errOut, "usage") {
		t.Errorf("no domains: %d %q", code, errOut)
	}
	if code, _, _ := runRenew("-bogus"); code != 2 {
		t.Errorf("bad flag: want 2, got %d", code)
	}
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0600)
	if code, out, _ := runRenew("-config", bad, "a.example.com"); code != 1 || !strings.Contains(out, "failed to load config") {
		t.Errorf("bad config: %d %s", code, out)
	}
	cfg := config.DefaultConfig()
	cfg.ACME.CertDir = filepath.Join(bad, "certs") // under a regular file
	data, _ := json.Marshal(cfg)
	path := filepath.Join(dir, "p.json")
	_ = os.WriteFile(path, data, 0640)
	if code, out, _ := runRenew("-config", path, "a.example.com"); code != 1 || !strings.Contains(out, "failed to init ACME client") {
		t.Errorf("ACME init: %d %s", code, out)
	}
}
