// Extra tests to lift certmanager coverage.
package certmanager

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/config"
)

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManager_NotNil(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	if m == nil {
		t.Error("NewManager returned nil")
	}
}

func TestNewManager_InFlightMapInitialized(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	if m.inFlight == nil {
		t.Error("inFlight map should be initialized")
	}
}

// ─── GetMetrics ───────────────────────────────────────────────────────────────

func TestGetMetrics_InitiallyZero(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	metrics := m.GetMetrics()
	if metrics.RenewalSuccess != 0 {
		t.Errorf("RenewalSuccess: want 0, got %d", metrics.RenewalSuccess)
	}
	if metrics.RenewalFailed != 0 {
		t.Errorf("RenewalFailed: want 0, got %d", metrics.RenewalFailed)
	}
}

func TestGetMetrics_AfterRecordSuccess(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	m.recordSuccess()
	metrics := m.GetMetrics()
	if metrics.RenewalSuccess != 1 {
		t.Errorf("RenewalSuccess: want 1, got %d", metrics.RenewalSuccess)
	}
	if metrics.RenewalFailed != 0 {
		t.Errorf("RenewalFailed: want 0, got %d", metrics.RenewalFailed)
	}
}

func TestGetMetrics_AfterRecordFailure(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	m.recordFailure()
	metrics := m.GetMetrics()
	if metrics.RenewalFailed != 1 {
		t.Errorf("RenewalFailed: want 1, got %d", metrics.RenewalFailed)
	}
	if metrics.RenewalSuccess != 0 {
		t.Errorf("RenewalSuccess: want 0, got %d", metrics.RenewalSuccess)
	}
}

// ─── GetCertStatus ────────────────────────────────────────────────────────────

func TestGetCertStatus_ValidCert(t *testing.T) {
	dir := t.TempDir()
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	m := NewManager(nil, nil, nil, nil, noopLogger())
	status, err := m.GetCertStatus("example.com", certPath)
	if err != nil {
		t.Fatalf("GetCertStatus: %v", err)
	}
	if status.Domain != "example.com" {
		t.Errorf("Domain: want example.com, got %s", status.Domain)
	}
	if status.DaysRemaining < 58 || status.DaysRemaining > 61 {
		t.Errorf("DaysRemaining: want ~60, got %d", status.DaysRemaining)
	}
	if status.NeedsRenewal {
		t.Error("cert with 60 days remaining should not need renewal")
	}
}

func TestGetCertStatus_MissingFile(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	_, err := m.GetCertStatus("example.com", "/nonexistent/cert.pem")
	if err == nil {
		t.Error("expected error for missing cert file, got nil")
	}
}

// ─── CheckAndRenewAll ─────────────────────────────────────────────────────────

func TestCheckAndRenewAll_NilConfigManager(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	// Should return nil when cfgManager is nil
	if err := m.CheckAndRenewAll(context.Background()); err != nil {
		t.Errorf("CheckAndRenewAll with nil cfgManager: want nil, got %v", err)
	}
}

func TestCheckAndRenewAll_NoTLSRoutes(t *testing.T) {
	cfg := &mockConfigProvider{cfg: config.Config{
		Routes: []config.ProxyRoute{
			{ID: "r1", Domain: "example.com", TLSEnabled: false, Enabled: true},
		},
	}}
	m := NewManager(nil, nil, nil, cfg, noopLogger())
	if err := m.CheckAndRenewAll(context.Background()); err != nil {
		t.Errorf("CheckAndRenewAll with no TLS routes: want nil, got %v", err)
	}
}

func TestCheckAndRenewAll_DisabledRoutes_Skipped(t *testing.T) {
	cfg := &mockConfigProvider{cfg: config.Config{
		Routes: []config.ProxyRoute{
			{ID: "r1", Domain: "example.com", TLSEnabled: true, Enabled: false, CertFile: "/fake/cert.pem"},
		},
	}}
	m := NewManager(nil, nil, nil, cfg, noopLogger())
	// Disabled routes should be skipped, no error
	if err := m.CheckAndRenewAll(context.Background()); err != nil {
		t.Errorf("CheckAndRenewAll with disabled routes: want nil, got %v", err)
	}
}

// ─── CheckAndRenew ────────────────────────────────────────────────────────────

func TestCheckAndRenew_CertNotExpiring_NoRenewal(t *testing.T) {
	dir := t.TempDir()
	// Cert with 60 days remaining — no renewal needed
	notAfter := time.Now().Add(60 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	var renewCalled bool
	m := &Manager{
		inFlight: make(map[string]bool),
		logger:   noopLogger(),
		renewFunc: func(ctx context.Context, domain string) error {
			renewCalled = true
			return nil
		},
	}

	route := config.ProxyRoute{Domain: "example.com", CertFile: certPath}
	if err := m.CheckAndRenew(context.Background(), route); err != nil {
		t.Fatalf("CheckAndRenew: %v", err)
	}
	if renewCalled {
		t.Error("renewal should not have been called for non-expiring cert")
	}
}

// ─── RenewCert ────────────────────────────────────────────────────────────────

func TestRenewCert_NilACMEClient_ReturnsError(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	route := config.ProxyRoute{Domain: "example.com", CertFile: "/fake.pem"}
	err := m.RenewCert(context.Background(), route)
	if err == nil {
		t.Error("RenewCert with nil acmeClient: want error, got nil")
	}
	if err.Error() != "no ACME client configured" {
		t.Errorf("error message: want 'no ACME client configured', got %q", err.Error())
	}
}

// ─── hotReload ────────────────────────────────────────────────────────────────

func TestHotReload_NilProxyEngine_ReturnsError(t *testing.T) {
	m := NewManager(nil, nil, nil, nil, noopLogger())
	err := m.hotReload("example.com", "/fake/cert.pem", "/fake/key.pem")
	if err == nil {
		t.Error("hotReload with nil proxyEngine: want error, got nil")
	}
	if err.Error() != "no proxy engine configured" {
		t.Errorf("error message: want 'no proxy engine configured', got %q", err.Error())
	}
}

// ─── Start ────────────────────────────────────────────────────────────────────

func TestStart_DoesNotPanic(t *testing.T) {
	// Start launches a goroutine; just verify it does not panic on startup
	cfg := &mockConfigProvider{cfg: config.Config{
		Routes: []config.ProxyRoute{},
	}}
	m := NewManager(nil, nil, nil, cfg, noopLogger())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Should not panic
	m.Start(ctx)
}

// ─── CheckAndRenewAll with renewal error (continues) ─────────────────────────

func TestCheckAndRenewAll_RenewalError_ContinuesOtherRoutes(t *testing.T) {
	dir := t.TempDir()
	// Cert expiring in 5 days → needs renewal
	notAfter := time.Now().Add(5 * 24 * time.Hour)
	certPath, _ := generateSelfSignedCert(t, dir, notAfter)

	var renewedDomains []string
	cfg := &mockConfigProvider{cfg: config.Config{
		Routes: []config.ProxyRoute{
			{ID: "r1", Domain: "bad.example.com", TLSEnabled: true, Enabled: true, CertFile: "/nonexistent/cert.pem"},
			{ID: "r2", Domain: "good.example.com", TLSEnabled: true, Enabled: true, CertFile: certPath},
		},
	}}

	m := &Manager{
		inFlight:   make(map[string]bool),
		logger:     noopLogger(),
		cfgManager: cfg,
		renewFunc: func(ctx context.Context, domain string) error {
			if domain == "bad.example.com" {
				return fmt.Errorf("forced error")
			}
			renewedDomains = append(renewedDomains, domain)
			return nil
		},
	}

	// Should not return error even if individual routes fail
	if err := m.CheckAndRenewAll(context.Background()); err != nil {
		t.Errorf("CheckAndRenewAll: want nil, got %v", err)
	}
	// good.example.com should have been renewed (cert is expiring)
	found := false
	for _, d := range renewedDomains {
		if d == "good.example.com" {
			found = true
		}
	}
	if !found {
		t.Error("good.example.com with expiring cert should have been renewed")
	}
}
