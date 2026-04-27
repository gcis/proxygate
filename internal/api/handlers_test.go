package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/api"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

// serverSetup creates a real Server with all dependencies.
// gdHandler is the fake GoDaddy API handler; pass nil for a default empty handler.
func serverSetup(t *testing.T, gdHandler http.Handler) (http.Handler, *config.Manager) {
	t.Helper()
	if gdHandler == nil {
		gdHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("[]")) //nolint:errcheck
		})
	}
	gdSrv := httptest.NewServer(gdHandler)
	t.Cleanup(gdSrv.Close)

	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}

	acmeClient, err := acme.NewClient("test@example.com", filepath.Join(dir, "certs"), "https://acme-staging-v02.api.letsencrypt.org/directory", hSilentLogger())
	if err != nil {
		t.Fatalf("acme: %v", err)
	}

	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gdClient := godaddy.NewClient("key", "secret", gdSrv.URL, hSilentLogger())

	srv := api.NewServer(cfgMgr, engine, acmeClient, gdClient, nil, hSilentLogger())
	return srv, cfgMgr
}

// serverSetupUnconfiguredGodaddy creates a Server with an unconfigured GoDaddy client.
func serverSetupUnconfiguredGodaddy(t *testing.T) (http.Handler, *config.Manager) {
	t.Helper()
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	acmeClient, err := acme.NewClient("test@example.com", filepath.Join(dir, "certs"), "https://acme-staging-v02.api.letsencrypt.org/directory", hSilentLogger())
	if err != nil {
		t.Fatalf("acme: %v", err)
	}
	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gdClient := godaddy.NewClient("", "", "https://api.godaddy.com", hSilentLogger()) // not configured
	srv := api.NewServer(cfgMgr, engine, acmeClient, gdClient, nil, hSilentLogger())
	return srv, cfgMgr
}

// hSilentLogger returns a logger that discards output.
func hSilentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(999)}))
}

func jsonBodyH(t *testing.T, v interface{}) io.Reader {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return bytes.NewReader(data)
}

func doReq(srv http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	return w
}

// ─── Config handlers ─────────────────────────────────────────────────────────

func TestHandleGetConfig_Returns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleGetConfig_MasksGoDaddySecret(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	// Set a real secret in config
	cfgMgr.Update(func(cfg *config.Config) { //nolint:errcheck
		cfg.GoDaddy.APISecret = "my-real-secret"
	})
	w := doReq(srv, http.MethodGet, "/api/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	body := w.Body.String()
	if strings.Contains(body, "my-real-secret") {
		t.Error("response should not contain plaintext secret")
	}
	if !strings.Contains(body, "********") {
		t.Error("response should contain masked secret '********'")
	}
}

func TestHandleUpdateServerConfig_ValidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	payload := config.ServerConfig{HTTPPort: 8080, HTTPSPort: 8443, AdminPort: 9090}
	w := doReq(srv, http.MethodPut, "/api/config/server", jsonBodyH(t, payload))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleUpdateServerConfig_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPut, "/api/config/server", strings.NewReader("not-json{"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── Route handlers ───────────────────────────────────────────────────────────

func TestHandleListRoutes_EmptyReturns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/routes", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	// Should be a JSON array
	var routes []interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &routes); err != nil {
		t.Errorf("response should be JSON array: %v", err)
	}
}

func TestHandleCreateRoute_Valid(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	route := map[string]interface{}{
		"domain":      "example.com",
		"target_host": "localhost",
		"target_port": 3000,
		"enabled":     true,
	}
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, route))
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateRoute_MissingDomain(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	route := map[string]interface{}{
		"target_host": "localhost",
		"target_port": 3000,
	}
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, route))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateRoute_MissingTargetHost(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	route := map[string]interface{}{
		"domain":      "example.com",
		"target_port": 3000,
	}
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, route))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateRoute_MissingTargetPort(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	route := map[string]interface{}{
		"domain":      "example.com",
		"target_host": "localhost",
		"target_port": 0,
	}
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, route))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateRoute_InvalidDomainFormat(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	route := map[string]interface{}{
		"domain":      "example .com", // space in domain
		"target_host": "localhost",
		"target_port": 3000,
	}
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, route))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleCreateRoute_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/routes", strings.NewReader("{bad json"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleGetRoute_Exists(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	// Create a route directly
	err := cfgMgr.AddRoute(config.ProxyRoute{
		ID:         "test-route-1",
		Domain:     "gettest.example.com",
		TargetHost: "localhost",
		TargetPort: 4000,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	// Get the actual route to retrieve its ID
	cfg := cfgMgr.Get()
	var routeID string
	for _, r := range cfg.Routes {
		if r.Domain == "gettest.example.com" {
			routeID = r.ID
			break
		}
	}
	if routeID == "" {
		t.Fatal("route not found after creation")
	}
	w := doReq(srv, http.MethodGet, "/api/routes/"+routeID, nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGetRoute_NotFound(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/routes/nonexistent-id", nil)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

func TestHandleUpdateRoute_Valid(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	err := cfgMgr.AddRoute(config.ProxyRoute{
		Domain:     "update.example.com",
		TargetHost: "localhost",
		TargetPort: 5000,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	cfg := cfgMgr.Get()
	var routeID string
	for _, r := range cfg.Routes {
		if r.Domain == "update.example.com" {
			routeID = r.ID
			break
		}
	}

	updated := map[string]interface{}{
		"domain":      "update.example.com",
		"target_host": "remotehost",
		"target_port": 6000,
		"enabled":     true,
	}
	w := doReq(srv, http.MethodPut, "/api/routes/"+routeID, jsonBodyH(t, updated))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateRoute_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPut, "/api/routes/any-id", strings.NewReader("{bad"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleDeleteRoute_Valid(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	err := cfgMgr.AddRoute(config.ProxyRoute{
		Domain:     "delete.example.com",
		TargetHost: "localhost",
		TargetPort: 7000,
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	cfg := cfgMgr.Get()
	var routeID string
	for _, r := range cfg.Routes {
		if r.Domain == "delete.example.com" {
			routeID = r.ID
			break
		}
	}
	w := doReq(srv, http.MethodDelete, "/api/routes/"+routeID, nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── Health / Status ──────────────────────────────────────────────────────────

func TestHandleHealthz_Returns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/healthz", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status: want ok, got %s", body["status"])
	}
}

func TestHandleStatus_Returns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/status", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

// ─── ACME handlers ────────────────────────────────────────────────────────────

func TestHandleACMEChallenges_ReturnsEmptyList(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/acme/challenges", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
}

func TestHandleUpdateACMEConfig_Valid(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	payload := config.ACMEConfig{
		Email:      "test@example.com",
		Directory:  "https://acme-staging-v02.api.letsencrypt.org/directory",
		CertDir:    "/tmp/certs",
		UseStaging: true,
	}
	w := doReq(srv, http.MethodPut, "/api/acme/config", jsonBodyH(t, payload))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateACMEConfig_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPut, "/api/acme/config", strings.NewReader("{invalid"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── GoDaddy config handlers ──────────────────────────────────────────────────

func TestHandleUpdateGoDaddyConfig_Valid(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	payload := config.GoDaddyConfig{
		APIKey:    "newkey",
		APISecret: "newsecret",
		BaseURL:   "https://api.godaddy.com",
	}
	w := doReq(srv, http.MethodPut, "/api/godaddy/config", jsonBodyH(t, payload))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleUpdateGoDaddyConfig_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPut, "/api/godaddy/config", strings.NewReader("{invalid"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── GoDaddy verify ───────────────────────────────────────────────────────────

func TestHandleVerifyGoDaddy_NotConfigured(t *testing.T) {
	srv, _ := serverSetupUnconfiguredGodaddy(t)
	w := doReq(srv, http.MethodPost, "/api/godaddy/verify", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unconfigured client, got %d", w.Code)
	}
}

func TestHandleVerifyGoDaddy_Configured_Success(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"domain":"example.com","status":"ACTIVE"}]`)) //nolint:errcheck
	})
	srv, _ := serverSetup(t, gdHandler)
	w := doReq(srv, http.MethodPost, "/api/godaddy/verify", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── GoDaddy domains ─────────────────────────────────────────────────────────

func TestHandleListGoDaddyDomains_NotConfigured(t *testing.T) {
	srv, _ := serverSetupUnconfiguredGodaddy(t)
	w := doReq(srv, http.MethodGet, "/api/godaddy/domains", nil)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unconfigured client, got %d", w.Code)
	}
}

func TestHandleListGoDaddyDomains_Configured(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"domain":"example.com","status":"ACTIVE"}]`)) //nolint:errcheck
	})
	srv, _ := serverSetup(t, gdHandler)
	w := doReq(srv, http.MethodGet, "/api/godaddy/domains", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── GoDaddy DNS records ──────────────────────────────────────────────────────

func TestHandleListDNSRecords_ReturnsRecords(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`[{"type":"A","name":"@","data":"1.2.3.4","ttl":600}]`)) //nolint:errcheck
	})
	srv, _ := serverSetup(t, gdHandler)
	w := doReq(srv, http.MethodGet, "/api/godaddy/domains/example.com/records", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateDNSRecord_Valid(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, _ := serverSetup(t, gdHandler)
	record := map[string]interface{}{
		"type": "A",
		"name": "sub",
		"data": "1.2.3.4",
		"ttl":  600,
	}
	w := doReq(srv, http.MethodPost, "/api/godaddy/domains/example.com/records", jsonBodyH(t, record))
	if w.Code != http.StatusCreated {
		t.Errorf("want 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleCreateDNSRecord_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/godaddy/domains/example.com/records", strings.NewReader("{invalid"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestHandleDeleteDNSRecord_Valid(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	srv, _ := serverSetup(t, gdHandler)
	w := doReq(srv, http.MethodDelete, "/api/godaddy/domains/example.com/records/A/sub", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

// ─── Auto-DNS ─────────────────────────────────────────────────────────────────

func TestHandleAutoDNS_NotConfigured(t *testing.T) {
	srv, _ := serverSetupUnconfiguredGodaddy(t)
	payload := map[string]interface{}{
		"domain":    "example.com",
		"subdomain": "www",
		"ip":        "1.2.3.4",
		"type":      "A",
	}
	w := doReq(srv, http.MethodPost, "/api/godaddy/auto-dns", jsonBodyH(t, payload))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 for unconfigured client, got %d", w.Code)
	}
}

func TestHandleAutoDNS_ARecord(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, _ := serverSetup(t, gdHandler)
	payload := map[string]interface{}{
		"domain":    "example.com",
		"subdomain": "www",
		"ip":        "1.2.3.4",
		"type":      "A",
	}
	w := doReq(srv, http.MethodPost, "/api/godaddy/auto-dns", jsonBodyH(t, payload))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleAutoDNS_CNAMERecord(t *testing.T) {
	gdHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, _ := serverSetup(t, gdHandler)
	payload := map[string]interface{}{
		"domain":    "example.com",
		"subdomain": "www",
		"type":      "CNAME",
		"value":     "target.example.com",
	}
	w := doReq(srv, http.MethodPost, "/api/godaddy/auto-dns", jsonBodyH(t, payload))
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleAutoDNS_InvalidBody(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPost, "/api/godaddy/auto-dns", strings.NewReader("{invalid"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── Certs status ─────────────────────────────────────────────────────────────

func TestHandleCertsStatus_NoTLSRoutes(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/certs/status", nil)
	if w.Code != http.StatusOK {
		t.Errorf("want 200, got %d", w.Code)
	}
	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	// certs field should be absent or null (no TLS routes)
	if certs, ok := body["certs"]; ok && certs != nil {
		if arr, ok := certs.([]interface{}); ok && len(arr) > 0 {
			t.Error("expected empty certs list for no TLS routes")
		}
	}
}

// ─── CORS / ServeHTTP ─────────────────────────────────────────────────────────

func TestServeHTTP_OPTIONS_Returns200(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	req := httptest.NewRequest(http.MethodOptions, "/api/routes", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("OPTIONS preflight: want 200, got %d", w.Code)
	}
}

func TestServeHTTP_SetsCORSHeaders(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/healthz", nil)
	origin := w.Header().Get("Access-Control-Allow-Origin")
	if origin == "" {
		t.Error("Access-Control-Allow-Origin header should be set")
	}
}
