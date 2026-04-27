// Extra tests to lift API handler coverage.
package api_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"


	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/api"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

// serverSetupFakeACME creates a Server where the ACME client points at a
// non-existent local URL so that Register/RequestCertificate fail instantly
// without real network calls.
func serverSetupFakeACME(t *testing.T) (http.Handler, *config.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	// Port 1 is reserved and connection-refused immediately → ACME fails fast.
	acmeClient, err := acme.NewClient("test@example.com", filepath.Join(dir, "certs"),
		"http://127.0.0.1:1/acme/directory", hSilentLogger())
	if err != nil {
		t.Fatalf("acme: %v", err)
	}
	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gdClient := godaddy.NewClient("", "", "https://api.godaddy.com", hSilentLogger())
	srv := api.NewServer(cfgMgr, engine, acmeClient, gdClient, nil, hSilentLogger())
	return srv, cfgMgr
}

// ─── RequestLogger ────────────────────────────────────────────────────────────

func TestRequestLogger_LogsRequestAndCallsNext(t *testing.T) {
	called := false
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := api.RequestLogger(hSilentLogger())(inner)

	req := httptest.NewRequest(http.MethodGet, "/api/test", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("RequestLogger should call the next handler")
	}
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ─── Handler ─────────────────────────────────────────────────────────────────

func TestHandler_ReturnsNonNil(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	// The API server itself implements http.Handler — verify it responds.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code == 0 {
		t.Error("server Handler should produce a response code")
	}
}

// ─── CORS / OPTIONS ──────────────────────────────────────────────────────────

func TestServeHTTP_OPTIONS_Returns200_Extra(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	req := httptest.NewRequest(http.MethodOptions, "/api/config", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS should return 200, got %d", w.Code)
	}
}

// ─── handleUI ────────────────────────────────────────────────────────────────

func TestHandleUI_Root_Returns200OrNotFound(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/", nil)
	// Serve index.html (200) or 404 if no embedded UI built yet — never 500.
	if w.Code == http.StatusInternalServerError {
		t.Errorf("GET / should not 500, got: %s", w.Body.String())
	}
}

func TestHandleUI_IndexHTML_NeverPanics(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/index.html", nil)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("GET /index.html should not 500, got: %s", w.Body.String())
	}
}

func TestHandleUI_SPARoute_NeverPanics(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/dashboard/settings/unknown", nil)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("SPA route should not 500, got: %s", w.Body.String())
	}
}

// ─── handleACMERequest ───────────────────────────────────────────────────────

func TestHandleACMERequest_BadJSON_Returns400(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/acme/request", strings.NewReader("{invalid"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleACMERequest_EmptyDomain_Returns400(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/acme/request",
		jsonBodyH(t, map[string]string{"domain": ""}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleACMERequest_ValidDomain_ACMEFails_Returns500(t *testing.T) {
	// ACME client uses a non-existent local URL → Register returns error fast.
	srv, _ := serverSetupFakeACME(t)
	w := doReq(srv, http.MethodPost, "/api/acme/request",
		jsonBodyH(t, map[string]string{"domain": "example.com"}))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500 (ACME registration fails), got %d: %s", w.Code, w.Body.String())
	}
}

// ─── handleACMEComplete ──────────────────────────────────────────────────────

func TestHandleACMEComplete_BadJSON_Returns400(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/acme/complete", strings.NewReader("{bad"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleACMEComplete_EmptyDomain_Returns400(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/acme/complete",
		jsonBodyH(t, map[string]interface{}{"domain": "", "auto_dns": false}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleACMEComplete_NoPendingChallenge_Returns500(t *testing.T) {
	// No challenge was requested for this domain → CompleteChallengeAndFetchCert
	// returns "no pending challenge" immediately (no network call).
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/acme/complete",
		jsonBodyH(t, map[string]interface{}{
			"domain":   "no-challenge.example.com",
			"auto_dns": false,
		}))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500 (no pending challenge), got %d: %s", w.Code, w.Body.String())
	}
}

// ─── handleCertsStatus ───────────────────────────────────────────────────────

func TestHandleCertsStatus_WithTLSRoutes_NilCertMgr(t *testing.T) {
	// certMgr is nil in serverSetup; the handler should handle this gracefully.
	srv, cfgMgr := serverSetup(t, nil)
	_ = cfgMgr.AddRoute(config.ProxyRoute{
		ID:         "tls-route-1",
		Domain:     "secure.example.com",
		TargetHost: "localhost",
		TargetPort: 443,
		TLSEnabled: true,
		CertFile:   "/tmp/fake-cert.pem",
		Enabled:    true,
	})
	w := doReq(srv, http.MethodGet, "/api/certs/status", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCertsStatus_NoRoutes_Returns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/certs/status", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleCertsStatus_NonTLSRoutes_EmptyCerts(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	_ = cfgMgr.AddRoute(config.ProxyRoute{
		ID:         "plain-route",
		Domain:     "plain.example.com",
		TargetHost: "localhost",
		TargetPort: 80,
		TLSEnabled: false,
		Enabled:    true,
	})
	w := doReq(srv, http.MethodGet, "/api/certs/status", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ─── Server.Handler ───────────────────────────────────────────────────────────

func TestServerHandler_ReturnsHTTPHandler(t *testing.T) {
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	acmeClient, err := acme.NewClient("test@example.com", filepath.Join(dir, "certs"),
		"https://acme-staging-v02.api.letsencrypt.org/directory", hSilentLogger())
	if err != nil {
		t.Fatalf("acme: %v", err)
	}
	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gdClient := godaddy.NewClient("", "", "https://api.godaddy.com", hSilentLogger())
	s := api.NewServer(cfgMgr, engine, acmeClient, gdClient, nil, hSilentLogger())

	h := s.Handler()
	if h == nil {
		t.Error("Handler() should return a non-nil http.Handler")
	}

	// Verify the returned handler responds to requests.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("want 200 from healthz via Handler(), got %d", w.Code)
	}
}

// ─── Server.Start (error path) ───────────────────────────────────────────────

func TestServerStart_PrivilegedPort_ReturnsError(t *testing.T) {
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	acmeClient, err := acme.NewClient("test@example.com", filepath.Join(dir, "certs"),
		"http://127.0.0.1:1/acme/directory", hSilentLogger())
	if err != nil {
		t.Fatalf("acme: %v", err)
	}
	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gdClient := godaddy.NewClient("", "", "https://api.godaddy.com", hSilentLogger())
	s := api.NewServer(cfgMgr, engine, acmeClient, gdClient, nil, hSilentLogger())

	// Port 1 is reserved/privileged — ListenAndServe returns immediately with error.
	err = s.Start(":1")
	if err == nil {
		t.Error("Start on privileged port should return an error")
	}
}
