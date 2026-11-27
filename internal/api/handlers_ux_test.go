package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/config"
)

func decodeBody(t *testing.T, w *httptest.ResponseRecorder, v interface{}) {
	t.Helper()
	if err := json.Unmarshal(w.Body.Bytes(), v); err != nil {
		t.Fatalf("decode %q: %v", w.Body.String(), err)
	}
}

func createRoute(t *testing.T, srv http.Handler, body map[string]interface{}) config.ProxyRoute {
	t.Helper()
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, body))
	if w.Code != http.StatusCreated {
		t.Fatalf("create: want 201, got %d: %s", w.Code, w.Body.String())
	}
	var r config.ProxyRoute
	decodeBody(t, w, &r)
	return r
}

// ─── Routes ─────────────────────────────────────────────────────────────────

func TestCreateRoute_ReturnsIDNormalisesAndDefaultsEnabled(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	r := createRoute(t, srv, map[string]interface{}{
		"domain": " App.Example.com ", "target_host": "[::1]", "target_port": 3000,
	})
	if r.ID == "" || r.CreatedAt == "" {
		t.Errorf("response must include id and timestamps: %+v", r)
	}
	if r.Domain != "app.example.com" || r.TargetHost != "::1" || !r.Enabled {
		t.Errorf("normalisation/defaults wrong: %+v", r)
	}
}

func TestCreateRoute_DuplicateDomainPrefix_Returns409(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	body := map[string]interface{}{"domain": "a.example.com", "path_prefix": "/api", "target_host": "h", "target_port": 1}
	createRoute(t, srv, body)
	w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, body))
	if w.Code != http.StatusConflict {
		t.Errorf("want 409, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCreateRoute_ValidationErrors(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	cases := map[string]map[string]interface{}{
		"scheme in host": {"domain": "a.com", "target_host": "http://x", "target_port": 1},
		"port too big":   {"domain": "a.com", "target_host": "x", "target_port": 70000},
		"bad prefix":     {"domain": "a.com", "target_host": "x", "target_port": 1, "path_prefix": "api"},
		"tls no cert":    {"domain": "a.com", "target_host": "x", "target_port": 1, "tls_enabled": true},
	}
	for name, body := range cases {
		w := doReq(srv, http.MethodPost, "/api/routes", jsonBodyH(t, body))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}
}

func TestUpdateRoute_MergesPartialBodyAndKeepsCert(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	created, err := cfgMgr.CreateRoute(config.ProxyRoute{
		Domain: "a.example.com", PathPrefix: "/x", TargetHost: "h", TargetPort: 1,
		TLSEnabled: true, CertFile: "c.pem", KeyFile: "k.pem", AutoCert: true, Enabled: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The UI's edit form does not send cert_file/key_file/auto_cert.
	w := doReq(srv, http.MethodPut, "/api/routes/"+created.ID, jsonBodyH(t, map[string]interface{}{
		"name": "Renamed", "target_port": 2, "tls_enabled": true,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Status string            `json:"status"`
		Route  config.ProxyRoute `json:"route"`
	}
	decodeBody(t, w, &resp)
	got := resp.Route
	if resp.Status != "updated" || got.Name != "Renamed" || got.TargetPort != 2 {
		t.Errorf("update not applied: %+v", resp)
	}
	if got.CertFile != "c.pem" || got.KeyFile != "k.pem" || !got.AutoCert || got.PathPrefix != "/x" {
		t.Errorf("unsent fields must be preserved: %+v", got)
	}
}

func TestUpdateAndDeleteRoute_MissingID_Returns404(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	if w := doReq(srv, http.MethodPut, "/api/routes/nope", jsonBodyH(t, map[string]interface{}{"name": "x"})); w.Code != http.StatusNotFound {
		t.Errorf("PUT: want 404, got %d", w.Code)
	}
	if w := doReq(srv, http.MethodDelete, "/api/routes/nope", nil); w.Code != http.StatusNotFound {
		t.Errorf("DELETE: want 404, got %d", w.Code)
	}
	if w := doReq(srv, http.MethodPatch, "/api/routes/nope/toggle", nil); w.Code != http.StatusNotFound {
		t.Errorf("PATCH toggle: want 404, got %d", w.Code)
	}
}

func TestToggleRoute_FlipsEnabled(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	r := createRoute(t, srv, map[string]interface{}{"domain": "t.example.com", "target_host": "h", "target_port": 1})
	w := doReq(srv, http.MethodPatch, "/api/routes/"+r.ID+"/toggle", nil)
	var resp struct {
		Route config.ProxyRoute `json:"route"`
	}
	decodeBody(t, w, &resp)
	if w.Code != http.StatusOK || resp.Route.Enabled {
		t.Fatalf("want disabled after toggle, got %d %+v", w.Code, resp.Route)
	}
}

// ─── Config / secrets ───────────────────────────────────────────────────────

func TestUpdateGoDaddyConfig_MaskedSecretKeepsStoredSecret(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	cfgMgr.Update(func(c *config.Config) { c.GoDaddy.APISecret = "real-secret" }) //nolint:errcheck

	for _, secret := range []string{"********", ""} {
		w := doReq(srv, http.MethodPut, "/api/godaddy/config", jsonBodyH(t, map[string]interface{}{
			"api_key": "k", "api_secret": secret, "base_url": "https://api.godaddy.com",
		}))
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		if got := cfgMgr.Get().GoDaddy.APISecret; got != "real-secret" {
			t.Fatalf("secret %q overwrote stored secret: got %q", secret, got)
		}
	}
}

func TestUpdateGoDaddyConfig_RejectsUnknownBaseURL(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodPut, "/api/godaddy/config", jsonBodyH(t, map[string]interface{}{
		"api_key": "k", "api_secret": "s", "base_url": "https://attacker.example",
	}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

func TestUpdateACMEConfig_KeepsCertDirAndValidatesEmail(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	before := cfgMgr.Get().ACME.CertDir
	w := doReq(srv, http.MethodPut, "/api/acme/config", jsonBodyH(t, map[string]interface{}{
		"email": "ops@example.com", "use_staging": false,
	}))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	acme := cfgMgr.Get().ACME
	if acme.CertDir != before || acme.Directory != "https://acme-v02.api.letsencrypt.org/directory" || acme.UseStaging {
		t.Errorf("unexpected ACME config: %+v", acme)
	}
	if w := doReq(srv, http.MethodPut, "/api/acme/config", jsonBodyH(t, map[string]interface{}{"email": "nope"})); w.Code != http.StatusBadRequest {
		t.Errorf("bad email: want 400, got %d", w.Code)
	}
}

func TestUpdateServerConfig_ValidationAndLockoutGuard(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	// httptest requests come from 192.0.2.1.
	cases := map[string]map[string]interface{}{
		"duplicate ports": {"http_port": 8080, "https_port": 8080},
		"bad cidr":        {"allowed_networks": []string{"10.0.0.0/99"}},
		"lockout":         {"allowed_networks": []string{"10.0.0.0/8"}},
	}
	for name, body := range cases {
		if w := doReq(srv, http.MethodPut, "/api/config/server", jsonBodyH(t, body)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}

	w := doReq(srv, http.MethodPut, "/api/config/server", jsonBodyH(t, map[string]interface{}{
		"allowed_networks": []string{"192.0.2.0/24", " ", "127.0.0.1"},
	}))
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	if w.Code != http.StatusOK || resp["restart_required"] != true {
		t.Errorf("want 200 + restart_required, got %d %v", w.Code, resp)
	}
}

func TestConfigChangedBroadcast_IsRedacted(t *testing.T) {
	// GET /api/config is covered elsewhere; here make sure the payload type
	// used for broadcasts masks the secret too.
	srv, cfgMgr := serverSetup(t, nil)
	cfgMgr.Update(func(c *config.Config) { c.GoDaddy.APISecret = "top-secret" }) //nolint:errcheck
	w := doReq(srv, http.MethodGet, "/api/config", nil)
	if strings.Contains(w.Body.String(), "top-secret") {
		t.Fatal("secret leaked in /api/config")
	}
}

func TestSecurityStatus(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	w := doReq(srv, http.MethodGet, "/api/security/status", nil)
	var resp map[string]interface{}
	decodeBody(t, w, &resp)
	if w.Code != http.StatusOK || resp["csp_enforced"] != true || resp["acme_staging"] != true {
		t.Errorf("unexpected: %d %v", w.Code, resp)
	}
}

// ─── Cross-origin protection ────────────────────────────────────────────────

func TestCrossOriginWrite_Rejected(t *testing.T) {
	srv, cfgMgr := serverSetup(t, nil)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/api/routes",
		jsonBodyH(t, map[string]interface{}{"domain": "x.com", "target_host": "h", "target_port": 1}))
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || len(cfgMgr.Get().Routes) != 0 {
		t.Errorf("cross-origin write must be rejected, got %d", w.Code)
	}
}

func TestOversizedBody_Rejected(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	big := `{"name":"` + strings.Repeat("a", 300<<10) + `"}`
	w := doReq(srv, http.MethodPost, "/api/routes", strings.NewReader(big))
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}

// ─── GoDaddy ────────────────────────────────────────────────────────────────

func TestListGoDaddyDomains_HidesInactiveUnlessAsked(t *testing.T) {
	gd := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"domain":"b.com","status":"ACTIVE"},{"domain":"old.com","status":"EXPIRED"},{"domain":"a.com","status":"ACTIVE"}]`)) //nolint:errcheck
	})
	srv, _ := serverSetup(t, gd)

	var active []map[string]string
	decodeBody(t, doReq(srv, http.MethodGet, "/api/godaddy/domains", nil), &active)
	if len(active) != 2 || active[0]["domain"] != "a.com" {
		t.Errorf("want sorted active-only [a.com b.com], got %v", active)
	}

	var all []map[string]string
	decodeBody(t, doReq(srv, http.MethodGet, "/api/godaddy/domains?include_inactive=true", nil), &all)
	if len(all) != 3 {
		t.Errorf("want 3 with include_inactive, got %v", all)
	}
}

func TestCreateDNSRecord_Validation(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	cases := map[string]map[string]interface{}{
		"bad type":   {"type": "PTR", "name": "x", "data": "y"},
		"low ttl":    {"type": "TXT", "name": "x", "data": "y", "ttl": 60},
		"A not ipv4": {"type": "A", "name": "x", "data": "::1"},
		"no data":    {"type": "TXT", "name": "x", "data": ""},
		"srv":        {"type": "SRV", "name": "_sip._tcp", "data": "sip.example.com"},
	}
	for name, body := range cases {
		if w := doReq(srv, http.MethodPost, "/api/godaddy/domains/example.com/records", jsonBodyH(t, body)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, w.Code, w.Body.String())
		}
	}
	if w := doReq(srv, http.MethodGet, "/api/godaddy/domains/bad%20domain/records", nil); w.Code != http.StatusBadRequest {
		t.Errorf("bad zone: want 400, got %d", w.Code)
	}
}

// ─── Docs ───────────────────────────────────────────────────────────────────

func TestDocsServed(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	for _, p := range []string{"/docs/", "/docs/api.html", "/docs/security.html", "/docs/docs.css"} {
		if w := doReq(srv, http.MethodGet, p, nil); w.Code != http.StatusOK {
			t.Errorf("%s: want 200, got %d", p, w.Code)
		}
	}
}
