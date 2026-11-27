package certmanager

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/config"
)

type fakeRequester struct {
	certPath, keyPath string
	err               error
	calls             []string
}

func (f *fakeRequester) RenewForDomain(_ context.Context, domain string) (string, string, error) {
	f.calls = append(f.calls, domain)
	return f.certPath, f.keyPath, f.err
}

type fakeReloader struct {
	loaded []string
	err    error
}

func (f *fakeReloader) LoadCertificate(domain, _, _ string) error {
	f.loaded = append(f.loaded, domain)
	return f.err
}

type staticConfig struct{ cfg config.Config }

func (s staticConfig) Get() config.Config { return s.cfg }

func expiringRoute(t *testing.T, domain string, notAfter time.Time) config.ProxyRoute {
	t.Helper()
	cert, key := generateSelfSignedCert(t, t.TempDir(), notAfter)
	return config.ProxyRoute{ID: domain, Domain: domain, TLSEnabled: true, Enabled: true, CertFile: cert, KeyFile: key}
}

func TestCheckAndRenewAll_RenewsExpiringCertAndHotReloads(t *testing.T) {
	soon := expiringRoute(t, "soon.example.com", time.Now().Add(5*24*time.Hour))
	later := expiringRoute(t, "later.example.com", time.Now().Add(80*24*time.Hour))
	req := &fakeRequester{certPath: "/new.pem", keyPath: "/new.key"}
	rel := &fakeReloader{}
	m := NewManager(rel, req, nil, staticConfig{config.Config{Routes: []config.ProxyRoute{soon, later}}}, noopLogger())

	if err := m.CheckAndRenewAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(req.calls) != 1 || req.calls[0] != "soon.example.com" {
		t.Errorf("renewal requested for %v, want only soon.example.com", req.calls)
	}
	if len(rel.loaded) != 1 || rel.loaded[0] != "soon.example.com" {
		t.Errorf("hot reload: %v", rel.loaded)
	}
	if got := m.GetMetrics(); got.RenewalSuccess != 1 || got.RenewalFailed != 0 {
		t.Errorf("metrics: %+v", got)
	}
}

func TestRenewCert_Failures(t *testing.T) {
	route := expiringRoute(t, "x.example.com", time.Now().Add(time.Hour))
	boom := errors.New("acme down")

	m := NewManager(&fakeReloader{}, &fakeRequester{err: boom}, nil, nil, noopLogger())
	if err := m.RenewCert(context.Background(), route); !errors.Is(err, boom) {
		t.Errorf("requester error: %v", err)
	}

	reloadErr := errors.New("bad pair")
	m = NewManager(&fakeReloader{err: reloadErr}, &fakeRequester{certPath: "c", keyPath: "k"}, nil, nil, noopLogger())
	if err := m.RenewCert(context.Background(), route); !errors.Is(err, reloadErr) {
		t.Errorf("reload error: %v", err)
	}

	// Through CheckAndRenew the failure is counted.
	m = NewManager(&fakeReloader{}, &fakeRequester{err: boom}, nil, staticConfig{config.Config{Routes: []config.ProxyRoute{route}}}, noopLogger())
	if err := m.CheckAndRenew(context.Background(), route); err == nil {
		t.Error("expected failure")
	}
	if m.GetMetrics().RenewalFailed != 1 {
		t.Errorf("failure not counted: %+v", m.GetMetrics())
	}
}

func TestCheckAndRenew_UnreadableCertIsAnError(t *testing.T) {
	m := NewManager(&fakeReloader{}, &fakeRequester{}, nil, nil, noopLogger())
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a certificate"), 0600)
	if err := m.CheckAndRenew(context.Background(), config.ProxyRoute{Domain: "x", CertFile: bad}); err == nil {
		t.Error("garbage certificate must be reported")
	}
	if _, err := m.GetCertStatus("x", bad); err == nil {
		t.Error("GetCertStatus must report garbage certificate")
	}
}

func TestStart_RunsImmediatelyAndStopsOnCancel(t *testing.T) {
	route := expiringRoute(t, "boot.example.com", time.Now().Add(time.Hour))
	req := &fakeRequester{err: errors.New("offline")}
	m := NewManager(&fakeReloader{}, req, nil, staticConfig{config.Config{Routes: []config.ProxyRoute{route}}}, noopLogger())

	ctx, cancel := context.WithCancel(context.Background())
	m.Start(ctx)
	deadline := time.Now().Add(3 * time.Second)
	for m.GetMetrics().RenewalFailed == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if m.GetMetrics().RenewalFailed != 1 {
		t.Errorf("startup check did not run: %+v", m.GetMetrics())
	}
}

func TestAtomicWrite_RenameFailureCleansUp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil { // renaming a file onto a non-empty dir fails
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(target, "keep"), nil, 0600)
	if err := atomicWrite(target, []byte("x"), 0600); err == nil {
		t.Fatal("expected rename failure")
	}
	if _, err := os.Stat(target + ".tmp"); !os.IsNotExist(err) {
		t.Error("temporary file must be removed after a failed rename")
	}

	m := NewManager(nil, nil, nil, nil, noopLogger())
	if err := m.AtomicWriteCert(filepath.Join(dir, "ok.pem"), target, []byte("c"), []byte("k")); err == nil {
		t.Error("key write failure must be reported")
	}
}

func TestBackoffDuration_NegativeAttempt(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	if d := m.backoffDuration(-3); d != time.Minute {
		t.Errorf("negative attempt: %v", d)
	}
}
