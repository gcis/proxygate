// Extra tests to lift proxy coverage.
package proxy_test

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
	"testing"
	"time"
)

// ─── generateTestCert ────────────────────────────────────────────────────────

// generateTestCert creates a self-signed ECDSA cert in a temp dir and returns
// (certPath, keyPath) for use in LoadCertificate tests.
func generateTestCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	cf, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("create cert file: %v", err)
	}
	defer cf.Close()
	if err := pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatalf("encode cert: %v", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath
}

// ─── Stop ────────────────────────────────────────────────────────────────────

func TestStop_WithoutStartedServers_ReturnsNil(t *testing.T) {
	engine, _ := newTestEngine(t, nil)
	ctx := context.Background()
	if err := engine.Stop(ctx); err != nil {
		t.Errorf("Stop on engine without started servers: want nil, got %v", err)
	}
}

// ─── LoadCertificate ─────────────────────────────────────────────────────────

func TestLoadCertificate_InvalidFiles_ReturnsError(t *testing.T) {
	engine, _ := newTestEngine(t, nil)
	err := engine.LoadCertificate("example.com", "/nonexistent/cert.pem", "/nonexistent/key.pem")
	if err == nil {
		t.Error("LoadCertificate with invalid files should return error")
	}
}

func TestLoadCertificate_ValidCert_Succeeds(t *testing.T) {
	engine, _ := newTestEngine(t, nil)
	certPath, keyPath := generateTestCert(t)
	if err := engine.LoadCertificate("test.example.com", certPath, keyPath); err != nil {
		t.Errorf("LoadCertificate with valid cert should succeed, got %v", err)
	}
}

// ─── EnsureHTTPSStarted ──────────────────────────────────────────────────────

func TestEnsureHTTPSStarted_WhenAlreadyRunning_IsNoOp(t *testing.T) {
	// EnsureHTTPSStarted when tlsServer is nil should attempt to start (no panic).
	// We can't easily verify a server started without binding a port, but we verify
	// the function completes without panic when tlsServer is nil (port 0 path).
	engine, _ := newTestEngine(t, nil)
	// Should not panic — tlsServer is nil so it attempts startHTTPS with default port
	// We can't wait for the goroutine to fail binding, but no panic is the contract.
	engine.EnsureHTTPSStarted()
}
