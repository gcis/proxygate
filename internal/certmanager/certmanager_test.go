// Tests for the certmanager package.
package certmanager

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/config"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// generateSelfSignedCert creates a self-signed cert that expires at notAfter
// and writes it to certPath/keyPath, returning both paths.
func generateSelfSignedCert(t *testing.T, dir string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     []string{"test.example.com"},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	certFile, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// ─── TestNeedsRenewal ─────────────────────────────────────────────────────────

func TestNeedsRenewal_ExpiringSoon_Needs(t *testing.T) {
	dir := t.TempDir()
	// Cert expires in 29 days → should need renewal
	notAfter := time.Now().Add(29 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	m := &Manager{}
	needs, err := m.NeedsRenewal(certPath)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !needs {
		t.Error("cert expiring in 29 days should need renewal")
	}
}

func TestNeedsRenewal_ExpiringLater_DoesNotNeed(t *testing.T) {
	dir := t.TempDir()
	// Cert expires in 31 days → no renewal needed
	notAfter := time.Now().Add(31 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	m := &Manager{}
	needs, err := m.NeedsRenewal(certPath)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if needs {
		t.Error("cert expiring in 31 days should NOT need renewal")
	}
}

func TestRenewalThreshold30Days(t *testing.T) {
	dir := t.TempDir()
	// Exactly 30 days remaining → boundary: should trigger renewal
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	m := &Manager{}
	needs, err := m.NeedsRenewal(certPath)
	if err != nil {
		t.Fatalf("NeedsRenewal: %v", err)
	}
	if !needs {
		t.Error("cert with exactly 30 days remaining should trigger renewal (threshold is <= 30 days)")
	}
}

func TestNeedsRenewal_MissingFile_ReturnsError(t *testing.T) {
	m := &Manager{}
	_, err := m.NeedsRenewal("/nonexistent/cert.pem")
	if err == nil {
		t.Error("expected error for missing cert file, got nil")
	}
}

// ─── TestAtomicCertWrite ──────────────────────────────────────────────────────

func TestAtomicCertWrite(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----\n")
	keyPEM := []byte("-----BEGIN EC PRIVATE KEY-----\nMIIBkey\n-----END EC PRIVATE KEY-----\n")

	m := &Manager{}
	if err := m.AtomicWriteCert(certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("AtomicWriteCert: %v", err)
	}

	gotCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("reading cert: %v", err)
	}
	if string(gotCert) != string(certPEM) {
		t.Errorf("cert content mismatch: want %q, got %q", certPEM, gotCert)
	}

	gotKey, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("reading key: %v", err)
	}
	if string(gotKey) != string(keyPEM) {
		t.Errorf("key content mismatch: want %q, got %q", keyPEM, gotKey)
	}
}

func TestAtomicCertWriteFailure_DirNotExist(t *testing.T) {
	m := &Manager{}
	err := m.AtomicWriteCert(
		"/nonexistent/deep/path/cert.pem",
		"/nonexistent/deep/path/key.pem",
		[]byte("cert"),
		[]byte("key"),
	)
	if err == nil {
		t.Error("expected error writing to non-existent directory, got nil")
	}
}

// ─── TestRenewalCounters ──────────────────────────────────────────────────────

func TestRenewalCounters(t *testing.T) {
	m := &Manager{}
	const n = 3

	for i := 0; i < n; i++ {
		m.recordSuccess()
	}

	got := atomic.LoadInt64(&m.metrics.RenewalSuccess)
	if got != n {
		t.Errorf("RenewalSuccess: want %d, got %d", n, got)
	}
	if atomic.LoadInt64(&m.metrics.RenewalFailed) != 0 {
		t.Error("RenewalFailed should still be 0")
	}
}

// ─── TestFailureBackoff ───────────────────────────────────────────────────────

func TestFailureBackoff(t *testing.T) {
	m := &Manager{}

	d0 := m.backoffDuration(0) // 1 min
	d1 := m.backoffDuration(1) // 2 min
	d2 := m.backoffDuration(2) // 4 min
	dMax := m.backoffDuration(100) // capped at 1 hour

	if d0 != time.Minute {
		t.Errorf("attempt 0: want 1m, got %v", d0)
	}
	if d1 != 2*time.Minute {
		t.Errorf("attempt 1: want 2m, got %v", d1)
	}
	if d2 != 4*time.Minute {
		t.Errorf("attempt 2: want 4m, got %v", d2)
	}
	if dMax != time.Hour {
		t.Errorf("attempt 100: want 1h (cap), got %v", dMax)
	}
}

// ─── TestConcurrentRenewalSafety ──────────────────────────────────────────────

func TestConcurrentRenewalSafety(t *testing.T) {
	// Count how many times the actual renewal func is called.
	var renewCalls int64

	m := &Manager{
		inFlight: make(map[string]bool),
		logger:   noopLogger(),
	}

	// Override the renewal function via a test hook
	m.renewFunc = func(ctx context.Context, domain string) error {
		atomic.AddInt64(&renewCalls, 1)
		// Simulate some work
		time.Sleep(10 * time.Millisecond)
		return nil
	}

	const goroutines = 10
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.checkAndRenewWithFunc(context.Background(), "app.example.com")
		}()
	}
	wg.Wait()

	// Only 1 renewal should have been triggered (in-flight dedup)
	if renewCalls != 1 {
		t.Errorf("expected 1 renewal call for concurrent requests, got %d", renewCalls)
	}
}

// ─── TestHotReload ────────────────────────────────────────────────────────────

func TestHotReload(t *testing.T) {
	var loadCalled int
	var lastDomain string

	reloader := &mockCertReloader{
		loadFunc: func(domain, certFile, keyFile string) error {
			loadCalled++
			lastDomain = domain
			return nil
		},
	}

	m := &Manager{
		proxyEngine: reloader,
		logger:      noopLogger(),
		inFlight:    make(map[string]bool),
	}

	dir := t.TempDir()
	notAfter := time.Now().Add(29 * 24 * time.Hour)
	certPath, keyPath := generateSelfSignedCert(t, dir, notAfter)

	if err := m.hotReload("app.example.com", certPath, keyPath); err != nil {
		t.Fatalf("hotReload: %v", err)
	}

	if loadCalled != 1 {
		t.Errorf("LoadCertificate called %d times, want 1", loadCalled)
	}
	if lastDomain != "app.example.com" {
		t.Errorf("domain: want app.example.com, got %s", lastDomain)
	}
}

// ─── Mocks & helpers ──────────────────────────────────────────────────────────

type mockCertReloader struct {
	loadFunc func(domain, certFile, keyFile string) error
}

func (m *mockCertReloader) LoadCertificate(domain, certFile, keyFile string) error {
	return m.loadFunc(domain, certFile, keyFile)
}

type mockConfigProvider struct {
	cfg config.Config
}

func (m *mockConfigProvider) Get() config.Config {
	return m.cfg
}
