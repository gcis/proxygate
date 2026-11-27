package acme

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/acmetest"
)

func newFlowClient(t *testing.T, email string) (*Client, *acmetest.Server, string) {
	t.Helper()
	srv := acmetest.New()
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	c, err := NewClient(email, dir, srv.DirectoryURL(), silentLogger())
	if err != nil {
		t.Fatal(err)
	}
	return c, srv, dir
}

func TestFullIssuanceFlow(t *testing.T) {
	c, _, dir := newFlowClient(t, "ops@example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := c.Register(ctx); err != nil {
		t.Fatalf("Register: %v", err)
	}
	st, err := c.RequestCertificate(ctx, "app.example.com")
	if err != nil {
		t.Fatalf("RequestCertificate: %v", err)
	}
	if st.Status != "pending" || st.RecordName != "_acme-challenge.app.example.com" || st.RecordVal == "" {
		t.Fatalf("challenge: %+v", st)
	}
	if got := c.GetChallengeStatus("app.example.com"); got == nil || got.RecordVal != st.RecordVal {
		t.Fatalf("GetChallengeStatus: %+v", got)
	}

	certPath, keyPath, err := c.CompleteChallengeAndFetchCert(ctx, "app.example.com")
	if err != nil {
		t.Fatalf("CompleteChallengeAndFetchCert: %v", err)
	}
	if certPath != filepath.Join(dir, "app.example.com.pem") || keyPath != filepath.Join(dir, "app.example.com.key") {
		t.Errorf("paths: %s %s", certPath, keyPath)
	}
	data, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(cert.DNSNames) != 1 || cert.DNSNames[0] != "app.example.com" {
		t.Fatalf("issued cert: %v %v", err, cert)
	}
	if strings.Count(string(data), "BEGIN CERTIFICATE") != 2 {
		t.Error("cert file should hold the full chain")
	}
	if info, _ := os.Stat(keyPath); info.Mode().Perm() != 0600 {
		t.Errorf("key mode: %v", info.Mode().Perm())
	}
	if got := c.GetChallengeStatus("app.example.com"); got.Status != "valid" {
		t.Errorf("status after issuance: %+v", got)
	}
	if all := c.GetAllChallenges(); len(all) != 1 {
		t.Errorf("GetAllChallenges: %+v", all)
	}
}

func TestRegisterWithoutEmailOmitsContact(t *testing.T) {
	c, _, _ := newFlowClient(t, "")
	if err := c.Register(context.Background()); err != nil {
		t.Fatalf("Register without email: %v", err)
	}
}

func TestFailedValidationMarksChallengeInvalid(t *testing.T) {
	c, srv, _ := newFlowClient(t, "ops@example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.RequestCertificate(ctx, "bad.example.com"); err != nil {
		t.Fatal(err)
	}
	srv.FailValidation.Store(true)

	if _, _, err := c.CompleteChallengeAndFetchCert(ctx, "bad.example.com"); err == nil {
		t.Fatal("expected failure when the CA cannot validate the TXT record")
	}
	st := c.GetChallengeStatus("bad.example.com")
	if st.Status != "invalid" || st.Error == "" {
		t.Errorf("status after failure: %+v", st)
	}
}

func TestCompleteWithoutOrder(t *testing.T) {
	c, _, _ := newFlowClient(t, "ops@example.com")
	c.challenges["x.example.com"] = &ChallengeStatus{Domain: "x.example.com", Status: "pending"}
	if _, _, err := c.CompleteChallengeAndFetchCert(context.Background(), "x.example.com"); err == nil || !strings.Contains(err.Error(), "no pending order") {
		t.Errorf("want 'no pending order', got %v", err)
	}
}

func TestCompleteWithUnknownOrder(t *testing.T) {
	c, srv, _ := newFlowClient(t, "ops@example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.Register(ctx); err != nil {
		t.Fatal(err)
	}
	c.challenges["x.example.com"] = &ChallengeStatus{Domain: "x.example.com", Status: "pending"}
	c.orders["x.example.com"] = pendingOrder{orderURI: srv.URL + "/order/missing", authzURL: srv.URL + "/authz/missing"}
	if _, _, err := c.CompleteChallengeAndFetchCert(ctx, "x.example.com"); err == nil {
		t.Fatal("expected error for an order the CA does not know")
	}
	if st := c.GetChallengeStatus("x.example.com"); st.Status != "invalid" {
		t.Errorf("status: %+v", st)
	}
}

func TestCompleteWritesFailWhenCertDirGone(t *testing.T) {
	c, _, dir := newFlowClient(t, "ops@example.com")
	ctx := context.Background()
	if _, err := c.RequestCertificate(ctx, "gone.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.CompleteChallengeAndFetchCert(ctx, "gone.example.com"); err == nil || !strings.Contains(err.Error(), "cert file") {
		t.Errorf("want cert file error, got %v", err)
	}
}

func TestLoadOrCreateAccountKey_Errors(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	_ = os.WriteFile(path, []byte("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"), 0600)
	if _, err := loadOrCreateAccountKey(path); err == nil {
		t.Error("PEM with garbage key bytes must fail")
	}
	if _, err := loadOrCreateAccountKey(filepath.Join(dir, "missing-dir", "account.key")); err == nil {
		t.Error("unwritable key path must fail")
	}
	if _, err := NewClient("", path, "https://example.invalid/dir", silentLogger()); err == nil {
		t.Error("cert dir that is a file must fail")
	}
}
