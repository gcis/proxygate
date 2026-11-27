package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/acmetest"
	"github.com/gcis/proxygate/internal/config"
)

// syncBuffer is a bytes.Buffer safe for the concurrent writes slog makes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// writeConfig writes a config with free ports into a fresh data dir.
func writeConfig(t *testing.T, mutate func(*config.Config)) (path string, cfg *config.Config) {
	t.Helper()
	dir := t.TempDir()
	cfg = config.DefaultConfig()
	cfg.Server.HTTPPort = freePort(t)
	cfg.Server.HTTPSPort = freePort(t)
	cfg.Server.AdminPort = freePort(t)
	cfg.ACME.CertDir = filepath.Join(dir, "certs")
	if mutate != nil {
		mutate(cfg)
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	path = filepath.Join(dir, "proxygate.json")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatal(err)
	}
	return path, cfg
}

func runCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	code := run(context.Background(), args, os.Stdin, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestRun_VersionHelpAndBadFlags(t *testing.T) {
	if code, out, _ := runCmd(t, "-version"); code != 0 || !strings.Contains(out, "proxygate dev") {
		t.Errorf("-version: %d %q", code, out)
	}
	if code, _, errOut := runCmd(t, "-h"); code != 0 || !strings.Contains(errOut, "proxygate passwd") {
		t.Errorf("-h: %d %q", code, errOut)
	}
	if code, _, _ := runCmd(t, "-no-such-flag"); code != 2 {
		t.Errorf("unknown flag: want 2, got %d", code)
	}
}

func TestRun_StartupFailures(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(bad, []byte("{not json"), 0600)
	if code, out, _ := runCmd(t, "-config", bad); code != 1 || !strings.Contains(out, "failed to load config") {
		t.Errorf("invalid config: %d %q", code, out)
	}

	// A corrupt admin-auth.json must stop startup rather than leave the
	// admin UI in an unknown state.
	path, _ := writeConfig(t, nil)
	_ = os.WriteFile(filepath.Join(filepath.Dir(path), "admin-auth.json"), []byte("{"), 0600)
	if code, out, _ := runCmd(t, "-config", path); code != 1 || !strings.Contains(out, "reading admin credentials") {
		t.Errorf("corrupt auth file: %d %q", code, out)
	}

	// The ACME client cannot create its cert dir under a regular file.
	path, _ = writeConfig(t, func(c *config.Config) { c.ACME.CertDir = bad + "/certs" })
	if code, out, _ := runCmd(t, "-config", path); code != 1 || !strings.Contains(out, "failed to init ACME client") {
		t.Errorf("ACME init: %d %q", code, out)
	}

	// The setup code cannot be written into a read-only data directory.
	path, _ = writeConfig(t, nil)
	roDir := filepath.Dir(path)
	if err := os.Chmod(roDir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0700) })
	if os.Geteuid() != 0 { // root ignores directory permissions
		if code, out, _ := runCmd(t, "-config", path); code != 1 || !strings.Contains(out, "creating setup code") {
			t.Errorf("read-only data dir: %d %q", code, out)
		}
	}
}

func waitForHealthz(t *testing.T, url string, client *http.Client) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := client.Get(url); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("admin API never became healthy at %s", url)
}

func startRun(t *testing.T, args ...string) (stop func() int, logs *syncBuffer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	logs = &syncBuffer{}
	done := make(chan int, 1)
	go func() { done <- run(ctx, args, os.Stdin, logs, logs) }()
	return func() int {
		cancel()
		select {
		case code := <-done:
			return code
		case <-time.After(15 * time.Second):
			t.Fatal("run did not shut down")
			return -1
		}
	}, logs
}

func TestRun_ServesAndShutsDownGracefully(t *testing.T) {
	path, cfg := writeConfig(t, nil)
	stop, logs := startRun(t, "-config", path, "-allow-network", "10.0.0.0/8", "-allow-network", "127.0.0.0/8")

	waitForHealthz(t, "http://127.0.0.1:"+itoa(cfg.Server.AdminPort)+"/healthz", http.DefaultClient)

	// The admin API is locked until setup.
	resp, err := http.Get("http://127.0.0.1:" + itoa(cfg.Server.AdminPort) + "/api/routes")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("api before setup: want 401, got %d", resp.StatusCode)
	}

	if code := stop(); code != 0 {
		t.Errorf("exit code: %d", code)
	}
	out := logs.String()
	for _, want := range []string{"applied CLI network allowlist", "admin UI is locked", "ProxyGate running", "shutdown complete"} {
		if !strings.Contains(out, want) {
			t.Errorf("log missing %q", want)
		}
	}

	code, err := os.ReadFile(filepath.Join(filepath.Dir(path), "setup-code"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, strings.TrimSpace(string(code))) {
		t.Error("setup code must never be logged")
	}

	saved, _ := config.NewManager(path)
	nets := strings.Join(saved.Get().Server.AllowedNetworks, ",")
	if strings.Count(nets, "10.0.0.0/8") != 1 || strings.Count(nets, "127.0.0.0/8") != 1 {
		t.Errorf("CLI networks must be merged without duplicates: %s", nets)
	}
}

func TestRun_AdminHTTPSAndUndecryptableSecrets(t *testing.T) {
	path, cfg := writeConfig(t, func(c *config.Config) {
		c.Security.AdminTLS.Enabled = true
		c.GoDaddy.APISecret = "enc:not-decryptable-without-the-key"
	})
	t.Setenv("PROXYGATE_CONFIG_KEY", "")
	stop, logs := startRun(t, "-config", path)

	insecure := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed test cert
	waitForHealthz(t, "https://127.0.0.1:"+itoa(cfg.Server.AdminPort)+"/healthz", insecure)

	if code := stop(); code != 0 {
		t.Errorf("exit code: %d", code)
	}
	out := logs.String()
	if !strings.Contains(out, "admin_ui=https://") || !strings.Contains(out, "cert_sha256=") {
		t.Errorf("HTTPS startup not logged: %s", out)
	}
	if !strings.Contains(out, "could not be decrypted") {
		t.Error("undecryptable secrets must be reported at startup")
	}
}

func TestRun_AdminListenerFailureKeepsRunning(t *testing.T) {
	// Occupy the admin port: the admin API fails, the proxy keeps running
	// until shutdown, and a busy proxy port is only logged.
	path, cfg := writeConfig(t, nil)
	l, err := net.Listen("tcp", "127.0.0.1:"+itoa(cfg.Server.AdminPort))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	stop, logs := startRun(t, "-config", path)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(logs.String(), "admin server stopped") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if code := stop(); code != 0 {
		t.Errorf("exit code: %d", code)
	}
	if !strings.Contains(logs.String(), "admin server stopped") {
		t.Errorf("admin listener failure not logged: %s", logs.String())
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func silentLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestMultiFlagAndConfigAdapter(t *testing.T) {
	var m multiFlag
	_ = m.Set("a")
	_ = m.Set("b")
	if m.String() != "[a b]" {
		t.Errorf("multiFlag: %s", m.String())
	}
	path, _ := writeConfig(t, nil)
	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := (&configProviderAdapter{mgr: mgr}).Get(); got.Server.AdminHost != "127.0.0.1" {
		t.Errorf("adapter: %+v", got.Server)
	}
}

// ─── acmeRequesterAdapter ───────────────────────────────────────────────────

type fakeDNS struct {
	mu      sync.Mutex
	created []string
	err     error
}

func (f *fakeDNS) CreateTXTRecord(_ context.Context, domain, name, value string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, name+"="+value)
	return f.err
}

func (f *fakeDNS) DeleteTXTRecord(context.Context, string, string) error { return nil }

func newAdapterClient(t *testing.T) (*acme.Client, *acmetest.Server) {
	t.Helper()
	srv := acmetest.New()
	t.Cleanup(srv.Close)
	c, err := acme.NewClient("ops@example.com", t.TempDir(), srv.DirectoryURL(), silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	return c, srv
}

func TestAcmeRequesterAdapter_RenewsThroughDNS(t *testing.T) {
	client, _ := newAdapterClient(t)
	dns := &fakeDNS{}
	a := &acmeRequesterAdapter{client: client, dns: dns, propagationWait: time.Millisecond}
	certPath, keyPath, err := a.RenewForDomain(context.Background(), "renew.example.com")
	if err != nil {
		t.Fatalf("RenewForDomain: %v", err)
	}
	if len(dns.created) != 1 || !strings.HasPrefix(dns.created[0], "_acme-challenge.renew.example.com=") {
		t.Errorf("TXT record not published: %v", dns.created)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Errorf("issued pair unusable: %v", err)
	}
}

func TestAcmeRequesterAdapter_Failures(t *testing.T) {
	ctx := context.Background()

	client, _ := newAdapterClient(t)
	if _, _, err := (&acmeRequesterAdapter{client: client}).RenewForDomain(ctx, "a.example.com"); err == nil || !strings.Contains(err.Error(), "no DNS provider") {
		t.Errorf("nil DNS: %v", err)
	}

	client, _ = newAdapterClient(t)
	boom := errors.New("godaddy down")
	if _, _, err := (&acmeRequesterAdapter{client: client, dns: &fakeDNS{err: boom}}).RenewForDomain(ctx, "a.example.com"); !errors.Is(err, boom) {
		t.Errorf("DNS error: %v", err)
	}

	client, _ = newAdapterClient(t)
	cctx, cancel := context.WithCancel(ctx)
	dns := &fakeDNS{}
	a := &acmeRequesterAdapter{client: client, dns: dns, propagationWait: time.Hour}
	go func() {
		for {
			dns.mu.Lock()
			n := len(dns.created)
			dns.mu.Unlock()
			if n > 0 {
				cancel()
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	if _, _, err := a.RenewForDomain(cctx, "a.example.com"); !errors.Is(err, context.Canceled) {
		t.Errorf("cancel during propagation wait: %v", err)
	}

	unreachable, err := acme.NewClient("", t.TempDir(), "http://127.0.0.1:1/directory", silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithTimeout(ctx, 5*time.Second)
	defer rcancel()
	if _, _, err := (&acmeRequesterAdapter{client: unreachable, dns: &fakeDNS{}}).RenewForDomain(rctx, "a.example.com"); err == nil || !strings.Contains(err.Error(), "acme register") {
		t.Errorf("unreachable CA: %v", err)
	}

	srv := acmetest.New()
	t.Cleanup(srv.Close)
	reqFail, _ := acme.NewClient("", t.TempDir(), srv.DirectoryURL(), silentLogger())
	if _, _, err := (&acmeRequesterAdapter{client: reqFail, dns: &fakeDNS{}}).RenewForDomain(ctx, ""); err == nil || !strings.Contains(err.Error(), "acme request") {
		t.Errorf("rejected order: %v", err)
	}
}
