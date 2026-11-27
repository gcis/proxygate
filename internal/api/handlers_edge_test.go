package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/auth"
)

func failingGoDaddy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"code":"UNAVAILABLE","message":"down"}`, http.StatusServiceUnavailable)
	})
}

func TestGoDaddyFailuresSurfaceAsErrors(t *testing.T) {
	srv, _ := serverSetup(t, failingGoDaddy())
	cases := []struct {
		method, path string
		body         map[string]interface{}
		want         int
	}{
		{http.MethodPost, "/api/godaddy/verify", nil, http.StatusBadRequest},
		{http.MethodGet, "/api/godaddy/domains", nil, http.StatusInternalServerError},
		{http.MethodGet, "/api/godaddy/domains/example.com/records", nil, http.StatusInternalServerError},
		{http.MethodPost, "/api/godaddy/domains/example.com/records", map[string]interface{}{"type": "TXT", "name": "x", "data": "y"}, http.StatusInternalServerError},
		{http.MethodDelete, "/api/godaddy/domains/example.com/records/TXT/x", nil, http.StatusInternalServerError},
		{http.MethodPost, "/api/godaddy/auto-dns", map[string]interface{}{"domain": "example.com", "subdomain": "www", "ip": "203.0.113.5"}, http.StatusInternalServerError},
	}
	for _, c := range cases {
		var w *httptest.ResponseRecorder
		if c.body != nil {
			w = doReq(srv, c.method, c.path, jsonBodyH(t, c.body))
		} else {
			w = doReq(srv, c.method, c.path, nil)
		}
		if w.Code != c.want {
			t.Errorf("%s %s: want %d, got %d: %s", c.method, c.path, c.want, w.Code, w.Body.String())
		}
	}
}

func TestDNSEndpointsWithoutGoDaddyCredentials(t *testing.T) {
	srv, _ := serverSetupUnconfiguredGodaddy(t) // authenticated, GoDaddy unset
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/api/godaddy/domains/example.com/records"},
		{http.MethodDelete, "/api/godaddy/domains/example.com/records/A/www"},
		{http.MethodPost, "/api/godaddy/verify"},
		{http.MethodGet, "/api/godaddy/domains"},
	} {
		if w := doReq(srv, c.method, c.path, nil); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "not configured") {
			t.Errorf("%s %s: want 400 not configured, got %d %s", c.method, c.path, w.Code, w.Body.String())
		}
	}
	w := doReq(srv, http.MethodPost, "/api/godaddy/domains/example.com/records", jsonBodyH(t, map[string]interface{}{"type": "TXT", "name": "x", "data": "y"}))
	if w.Code != http.StatusBadRequest {
		t.Errorf("create record without credentials: want 400, got %d", w.Code)
	}
}

func TestDNSRecordValidationEdges(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	bad := map[string]map[string]interface{}{
		"AAAA with IPv4": {"type": "AAAA", "name": "x", "data": "1.2.3.4"},
		"CNAME not host": {"type": "CNAME", "name": "x", "data": "not a host"},
		"bad name":       {"type": "TXT", "name": "a b", "data": "y"},
		"unknown field":  {"type": "TXT", "name": "x", "data": "y", "colour": "blue"},
		"ttl too high":   {"type": "TXT", "name": "x", "data": "y", "ttl": 90000},
		"missing type":   {"name": "x", "data": "y"},
	}
	for name, body := range bad {
		if w := doReq(srv, http.MethodPost, "/api/godaddy/domains/example.com/records", jsonBodyH(t, body)); w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", name, w.Code)
		}
	}
	if w := doReq(srv, http.MethodPost, "/api/godaddy/domains/*.example.com/records", jsonBodyH(t, map[string]interface{}{"type": "TXT", "name": "x", "data": "y"})); w.Code != http.StatusBadRequest {
		t.Errorf("wildcard zone: want 400, got %d", w.Code)
	}
	if w := doReq(srv, http.MethodDelete, "/api/godaddy/domains/example.com/records/PTR/x", nil); w.Code != http.StatusBadRequest {
		t.Errorf("delete unsupported type: want 400, got %d", w.Code)
	}
	if w := doReq(srv, http.MethodDelete, "/api/godaddy/domains/bad%20zone/records/A/x", nil); w.Code != http.StatusBadRequest {
		t.Errorf("delete bad zone: want 400, got %d", w.Code)
	}
	for name, body := range map[string]map[string]interface{}{
		"bad domain":    {"domain": "bad domain", "subdomain": "www", "ip": "1.2.3.4"},
		"CNAME no host": {"domain": "example.com", "subdomain": "www", "type": "CNAME", "value": "not a host"},
		"A not IPv4":    {"domain": "example.com", "subdomain": "www", "ip": "::1"},
	} {
		if w := doReq(srv, http.MethodPost, "/api/godaddy/auto-dns", jsonBodyH(t, body)); w.Code != http.StatusBadRequest {
			t.Errorf("auto-dns %s: want 400, got %d", name, w.Code)
		}
	}
	if w := doReq(srv, http.MethodPost, "/api/acme/complete", jsonBodyH(t, map[string]string{"domain": "bad domain"})); w.Code != http.StatusBadRequest {
		t.Errorf("acme complete bad domain: %d", w.Code)
	}
}

func TestAuthEdges(t *testing.T) {
	h, dir := rawServer(t, nil)
	c := &client{t: t, h: h, remote: "127.0.0.1:9"}

	for _, p := range []string{"/api/auth/setup", "/api/auth/login", "/api/auth/password"} {
		req := httptest.NewRequest(http.MethodPost, p, strings.NewReader("{not json"))
		req.RemoteAddr = "127.0.0.1:9"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusBadRequest && w.Code != http.StatusUnauthorized {
			t.Errorf("%s malformed body: got %d", p, w.Code)
		}
	}
	if w := c.do(http.MethodPost, "/api/auth/login", map[string]string{"password": "anything"}); w.Code != http.StatusConflict {
		t.Errorf("login before setup: want 409, got %d", w.Code)
	}

	_ = auth.NewStore(dir).SetPassword("first passphrase", nil)
	c.do(http.MethodPost, "/api/auth/login", map[string]string{"password": "first passphrase"})
	if w := c.do(http.MethodPost, "/api/auth/password", map[string]string{"current_password": "first passphrase", "new_password": "short"}); w.Code != http.StatusBadRequest {
		t.Errorf("weak new password: want 400, got %d", w.Code)
	}

	// Non-Bearer Authorization schemes are not accepted.
	req := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	req.Header.Set("Authorization", "Basic YWRtaW46eA==")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Basic auth: want 401, got %d", w.Code)
	}

	// A corrupt credentials file fails closed.
	_ = os.WriteFile(filepath.Join(dir, auth.AuthFileName), []byte("{"), 0600)
	if w := c.do(http.MethodGet, "/api/auth/status", nil); w.Code != http.StatusInternalServerError {
		t.Errorf("status with corrupt auth file: want 500, got %d", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("session with corrupt auth file must fail closed, got %d", w.Code)
	}
}

func TestAuthThrottlesSetupAndPasswordChange(t *testing.T) {
	h, dir := rawServer(t, nil)
	_ = setupCode(t, dir)
	c := &client{t: t, h: h, remote: "192.0.2.77:1"}
	for i := 0; i < 5; i++ {
		c.do(http.MethodPost, "/api/auth/setup", map[string]string{"setup_code": "WRONG", "password": "long enough pw"})
	}
	if w := c.do(http.MethodPost, "/api/auth/setup", map[string]string{"setup_code": "WRONG", "password": "long enough pw"}); w.Code != http.StatusTooManyRequests {
		t.Errorf("setup throttling: want 429, got %d", w.Code)
	}

	h2, dir2 := rawServer(t, nil)
	_ = auth.NewStore(dir2).SetPassword("right passphrase", nil)
	a := &client{t: t, h: h2, remote: "127.0.0.1:3"}
	a.do(http.MethodPost, "/api/auth/login", map[string]string{"password": "right passphrase"})
	for i := 0; i < 5; i++ {
		a.do(http.MethodPost, "/api/auth/password", map[string]string{"current_password": "wrong", "new_password": "another passphrase"})
	}
	if w := a.do(http.MethodPost, "/api/auth/password", map[string]string{"current_password": "right passphrase", "new_password": "another passphrase"}); w.Code != http.StatusTooManyRequests {
		t.Errorf("password-change throttling: want 429, got %d", w.Code)
	}
}

func TestSameOriginVariants(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	cases := []struct {
		origin, host, fwd string
		write             int
	}{
		{"null", "admin.local", "", http.StatusForbidden},
		{"https://edge.example.com", "127.0.0.1:9090", "edge.example.com", http.StatusOK},
		{"https://edge.example.com", "127.0.0.1:9090", "other.example.com, edge.example.com", http.StatusForbidden},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "http://"+c.host+"/api/godaddy/verify", nil)
		req.Header.Set("Origin", c.origin)
		if c.fwd != "" {
			req.Header.Set("X-Forwarded-Host", c.fwd)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, req)
		got := w.Code
		if got != http.StatusForbidden {
			got = http.StatusOK // any non-CSRF outcome
		}
		if got != c.write {
			t.Errorf("origin %q host %q fwd %q: want %d, got %d", c.origin, c.host, c.fwd, c.write, w.Code)
		}
	}
}

func TestUIServesExplicitIndexAndAssets(t *testing.T) {
	srv, _ := serverSetup(t, nil)
	if w := doReq(srv, http.MethodGet, "/index.html", nil); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ProxyGate") {
		t.Errorf("/index.html: %d", w.Code)
	}
	if w := doReq(srv, http.MethodGet, "/static/css/style.css", nil); w.Code != http.StatusOK {
		t.Errorf("asset: %d", w.Code)
	}
}
