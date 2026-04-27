// Package certmanager handles automatic TLS certificate renewal with hot reload.
//
// It runs a background goroutine that checks daily whether any TLS route's
// certificate is within 30 days of expiry.  When renewal is needed it runs
// the full ACME DNS-01 flow and hot-reloads the new cert into the proxy
// engine without restarting any listener.
package certmanager

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gcis/proxygate/internal/config"
)

const renewalThreshold = 30 * 24 * time.Hour // renew when < 30 days remain

// ─── Interfaces ───────────────────────────────────────────────────────────────

// CertReloader is implemented by proxy.Engine.
type CertReloader interface {
	LoadCertificate(domain, certFile, keyFile string) error
}

// CertRequester is implemented by acme.Client (via an adapter in main that
// satisfies this interface).  RenewCert calls these two methods in sequence:
// first to initiate the DNS-01 challenge, then to complete it and fetch the cert.
type CertRequester interface {
	// RenewForDomain performs the full ACME flow (request + complete) and
	// returns the paths to the new cert and key files.
	RenewForDomain(ctx context.Context, domain string) (certPath, keyPath string, err error)
}


// DNSProvider is implemented by godaddy.Client.
type DNSProvider interface {
	CreateTXTRecord(ctx context.Context, fullDomain, name, value string) error
	DeleteTXTRecord(ctx context.Context, fullDomain, name string) error
}

// ConfigProvider is a read-only view of configuration.
type ConfigProvider interface {
	Get() config.Config
}

// ─── Metrics ──────────────────────────────────────────────────────────────────

// Metrics holds atomic counters for cert renewal outcomes.
type Metrics struct {
	RenewalSuccess int64
	RenewalFailed  int64
}

// ─── Manager ──────────────────────────────────────────────────────────────────

// Manager handles certificate lifecycle: expiry detection, ACME renewal, and
// hot-reloading into the proxy engine.
type Manager struct {
	proxyEngine   CertReloader
	acmeClient    CertRequester
	godaddyClient DNSProvider
	cfgManager    ConfigProvider
	logger        *slog.Logger

	mu       sync.Mutex
	inFlight map[string]bool // domain → renewal in progress

	metrics Metrics

	// renewFunc is used by tests to override the actual renewal logic.
	renewFunc func(ctx context.Context, domain string) error
}

// NewManager creates a new certmanager.Manager.
func NewManager(
	proxyEngine CertReloader,
	acmeClient CertRequester,
	godaddyClient DNSProvider,
	cfgMgr ConfigProvider,
	logger *slog.Logger,
) *Manager {
	return &Manager{
		proxyEngine:   proxyEngine,
		acmeClient:    acmeClient,
		godaddyClient: godaddyClient,
		cfgManager:    cfgMgr,
		logger:        logger,
		inFlight:      make(map[string]bool),
	}
}

// Start launches a background goroutine that checks for renewals daily.
// It runs an immediate check on startup, then again every 24 hours.
// The goroutine stops when ctx is cancelled.
func (m *Manager) Start(ctx context.Context) {
	go func() {
		// Run immediately at start
		if err := m.CheckAndRenewAll(ctx); err != nil {
			m.logger.Error("cert check failed", "error", err)
		}

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := m.CheckAndRenewAll(ctx); err != nil {
					m.logger.Error("cert check failed", "error", err)
				}
			}
		}
	}()
}

// CheckAndRenewAll iterates all TLS routes and renews certs as needed.
func (m *Manager) CheckAndRenewAll(ctx context.Context) error {
	if m.cfgManager == nil {
		return nil
	}
	cfg := m.cfgManager.Get()
	for _, route := range cfg.Routes {
		if !route.TLSEnabled || !route.Enabled || route.CertFile == "" {
			continue
		}
		if err := m.CheckAndRenew(ctx, route); err != nil {
			m.logger.Error("renewal failed",
				"domain", route.Domain,
				"error", err,
			)
			// Continue checking other routes
		}
	}
	return nil
}

// CheckAndRenew checks whether the cert for route needs renewal and renews if needed.
// It uses in-flight dedup so concurrent calls for the same domain only trigger one renewal.
func (m *Manager) CheckAndRenew(ctx context.Context, route config.ProxyRoute) error {
	needs, err := m.NeedsRenewal(route.CertFile)
	if err != nil {
		return fmt.Errorf("checking cert expiry for %s: %w", route.Domain, err)
	}
	if !needs {
		return nil
	}
	return m.checkAndRenewWithFunc(ctx, route.Domain)
}

// checkAndRenewWithFunc handles in-flight dedup and delegates to renewFunc
// (or RenewCert if renewFunc is nil).
func (m *Manager) checkAndRenewWithFunc(ctx context.Context, domain string) error {
	m.mu.Lock()
	if m.inFlight[domain] {
		m.mu.Unlock()
		m.logger.Info("renewal already in progress, skipping", "domain", domain)
		return nil
	}
	m.inFlight[domain] = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		delete(m.inFlight, domain)
		m.mu.Unlock()
	}()

	var err error
	if m.renewFunc != nil {
		err = m.renewFunc(ctx, domain)
	} else {
		cfg := m.cfgManager.Get()
		for _, r := range cfg.Routes {
			if r.Domain == domain {
				err = m.RenewCert(ctx, r)
				break
			}
		}
	}

	if err != nil {
		m.recordFailure()
		return err
	}
	m.recordSuccess()
	return nil
}

// NeedsRenewal returns true when the certificate at certFile has less than
// 30 days of validity remaining (including exactly 30 days — boundary inclusive).
func (m *Manager) NeedsRenewal(certFile string) (bool, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return false, fmt.Errorf("reading cert file %s: %w", certFile, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("no PEM block found in %s", certFile)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parsing cert %s: %w", certFile, err)
	}

	remaining := time.Until(cert.NotAfter)
	return remaining <= renewalThreshold, nil
}

// AtomicWriteCert writes certPEM to certPath and keyPEM to keyPath atomically
// using a write-to-temp-then-rename pattern.  Both files are written in the
// same directory; if the directory does not exist the call fails.
func (m *Manager) AtomicWriteCert(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if err := atomicWrite(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("writing cert to %s: %w", certPath, err)
	}
	if err := atomicWrite(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("writing key to %s: %w", keyPath, err)
	}
	return nil
}

// atomicWrite writes data to path via a temporary file + rename.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp) //nolint:errcheck
		return err
	}
	return nil
}

// RenewCert performs the full ACME DNS-01 renewal flow for route and hot-reloads
// the new certificate into the proxy engine.
func (m *Manager) RenewCert(ctx context.Context, route config.ProxyRoute) error {
	if m.acmeClient == nil {
		return fmt.Errorf("no ACME client configured")
	}

	m.logger.Info("starting cert renewal",
		"domain", route.Domain,
		"expiry", "< 30 days",
	)

	// Perform the full ACME flow via the requester
	certPath, keyPath, err := m.acmeClient.RenewForDomain(ctx, route.Domain)
	if err != nil {
		return fmt.Errorf("ACME renewal: %w", err)
	}

	// Hot-reload into proxy engine
	if err := m.hotReload(route.Domain, certPath, keyPath); err != nil {
		return fmt.Errorf("hot-reloading cert: %w", err)
	}

	m.logger.Info("cert renewal complete",
		"domain", route.Domain,
		"cert", certPath,
	)
	return nil
}

// hotReload calls the proxy engine's LoadCertificate to update the in-memory
// cert map without restarting any listener.
func (m *Manager) hotReload(domain, certPath, keyPath string) error {
	if m.proxyEngine == nil {
		return fmt.Errorf("no proxy engine configured")
	}
	return m.proxyEngine.LoadCertificate(domain, certPath, keyPath)
}

// backoffDuration returns 1min * 2^attempt, capped at 1 hour.
func (m *Manager) backoffDuration(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	d := time.Minute
	for i := 0; i < attempt; i++ {
		d *= 2
		if d >= time.Hour {
			return time.Hour
		}
	}
	return d
}

// CertStatus describes the current state of a domain's certificate.
type CertStatus struct {
	Domain         string    `json:"domain"`
	CertFile       string    `json:"cert_file"`
	ExpiresAt      time.Time `json:"expires_at"`
	DaysRemaining  int       `json:"days_remaining"`
	NeedsRenewal   bool      `json:"needs_renewal"`
}

// GetCertStatus returns expiry information for a certificate file.
func (m *Manager) GetCertStatus(domain, certFile string) (*CertStatus, error) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("reading cert: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in cert file")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing cert: %w", err)
	}

	remaining := time.Until(cert.NotAfter)
	days := int(remaining.Hours() / 24)

	return &CertStatus{
		Domain:        domain,
		CertFile:      certFile,
		ExpiresAt:     cert.NotAfter,
		DaysRemaining: days,
		NeedsRenewal:  remaining <= renewalThreshold,
	}, nil
}

// GetMetrics returns a snapshot of renewal counters.
func (m *Manager) GetMetrics() Metrics {
	return Metrics{
		RenewalSuccess: atomic.LoadInt64(&m.metrics.RenewalSuccess),
		RenewalFailed:  atomic.LoadInt64(&m.metrics.RenewalFailed),
	}
}

func (m *Manager) recordSuccess() {
	atomic.AddInt64(&m.metrics.RenewalSuccess, 1)
}

func (m *Manager) recordFailure() {
	atomic.AddInt64(&m.metrics.RenewalFailed, 1)
}

// noopLogger returns a logger that discards all output.
func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: slog.Level(999),
	}))
}
