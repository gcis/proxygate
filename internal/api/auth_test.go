package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/api"
	"github.com/gcis/proxygate/internal/auth"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

// rawServer builds a server with no credentials attached to requests.
func rawServer(t *testing.T, mutate func(*config.Config)) (http.Handler, string) {
	t.Helper()
	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		if err := cfgMgr.Update(mutate); err != nil {
			t.Fatal(err)
		}
	}
	acmeClient, err := acme.NewClient("", filepath.Join(dir, "certs"), "https://acme-staging-v02.api.letsencrypt.org/directory", hSilentLogger())
	if err != nil {
		t.Fatal(err)
	}
	engine := proxy.NewEngine(cfgMgr, hSilentLogger())
	gd := godaddy.NewClient("", "", "https://api.godaddy.com", hSilentLogger())
	return api.NewServer(cfgMgr, engine, acmeClient, gd, nil, hSilentLogger()), dir
}

type client struct {
	t      *testing.T
	h      http.Handler
	remote string
	cookie *http.Cookie
}

func (c *client) do(method, path string, body interface{}) *httptest.ResponseRecorder {
	c.t.Helper()
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, jsonBodyH(c.t, body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if c.remote != "" {
		req.RemoteAddr = c.remote
	}
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == "proxygate_session" {
			if ck.MaxAge < 0 {
				c.cookie = nil
			} else {
				c.cookie = ck
			}
		}
	}
	return w
}

func setupCode(t *testing.T, dir string) string {
	t.Helper()
	path, err := auth.NewStore(dir).EnsureSetupCode()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestAuth_LockedByDefault(t *testing.T) {
	h, _ := rawServer(t, nil)
	c := &client{t: t, h: h}

	for _, p := range []string{"/api/routes", "/api/config", "/api/security/status", "/ws"} {
		if w := c.do(http.MethodGet, p, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401, got %d", p, w.Code)
		}
	}
	if w := c.do(http.MethodPost, "/api/routes", map[string]interface{}{"domain": "a.com", "target_host": "h", "target_port": 1}); w.Code != http.StatusUnauthorized {
		t.Errorf("POST /api/routes: want 401, got %d", w.Code)
	}
	for _, p := range []string{"/healthz", "/", "/static/js/app.js", "/docs/", "/api/auth/status"} {
		if w := c.do(http.MethodGet, p, nil); w.Code != http.StatusOK {
			t.Errorf("%s: want 200 (public), got %d", p, w.Code)
		}
	}

	var st map[string]interface{}
	_ = json.Unmarshal(c.do(http.MethodGet, "/api/auth/status", nil).Body.Bytes(), &st)
	if st["setup_required"] != true || st["authenticated"] != false || st["setup_code_path"] == nil {
		t.Errorf("status before setup: %v", st)
	}
}

func TestAuth_BadBearerTokenRejected(t *testing.T) {
	h, _ := rawServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/api/routes", nil)
	req.Header.Set("Authorization", "Bearer pgt_not-a-real-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", w.Code)
	}
}

func TestAuth_SetupLoginLogout(t *testing.T) {
	h, dir := rawServer(t, nil)
	code := setupCode(t, dir)
	c := &client{t: t, h: h, remote: "127.0.0.1:5000"}

	if w := c.do(http.MethodPost, "/api/auth/setup", map[string]interface{}{"setup_code": "AAAAA-BBBBB-CCCCC-DDDDD", "password": "long enough pw"}); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong code: want 401, got %d", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/auth/setup", map[string]interface{}{"setup_code": code, "password": "short"}); w.Code != http.StatusBadRequest {
		t.Errorf("weak password: want 400, got %d", w.Code)
	}

	w := c.do(http.MethodPost, "/api/auth/setup", map[string]interface{}{"setup_code": code, "password": "a long passphrase", "strong_password_policy": true})
	if w.Code != http.StatusOK || c.cookie == nil {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	if !c.cookie.HttpOnly || c.cookie.SameSite != http.SameSiteStrictMode || c.cookie.Path != "/" {
		t.Errorf("cookie flags: %+v", c.cookie)
	}
	if w := c.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusOK {
		t.Errorf("session after setup: want 200, got %d", w.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, auth.SetupCodeFileName)); !os.IsNotExist(err) {
		t.Error("setup code must be removed after setup")
	}
	if w := c.do(http.MethodPost, "/api/auth/setup", map[string]interface{}{"setup_code": code, "password": "another passphrase"}); w.Code != http.StatusConflict {
		t.Errorf("second setup: want 409, got %d", w.Code)
	}

	// Logout ends the session.
	old := c.cookie
	c.do(http.MethodPost, "/api/auth/logout", nil)
	c.cookie = old
	if w := c.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("after logout: want 401, got %d", w.Code)
	}

	c.cookie = nil
	if w := c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "wrong password"}); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: want 401, got %d", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "a long passphrase"}); w.Code != http.StatusOK || c.cookie == nil {
		t.Fatalf("login: %d", w.Code)
	}
	if w := c.do(http.MethodGet, "/api/config", nil); w.Code != http.StatusOK {
		t.Errorf("after login: want 200, got %d", w.Code)
	}
}

func TestAuth_LoginThrottled(t *testing.T) {
	h, dir := rawServer(t, nil)
	if err := auth.NewStore(dir).SetPassword("the right password", nil); err != nil {
		t.Fatal(err)
	}
	c := &client{t: t, h: h, remote: "192.0.2.50:1234"}
	for i := 0; i < 5; i++ {
		c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "nope nope"})
	}
	w := c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "the right password"})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Errorf("want 429 with Retry-After even for the right password, got %d", w.Code)
	}
	other := &client{t: t, h: h, remote: "192.0.2.51:1234"}
	if w := other.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "the right password"}); w.Code != http.StatusOK {
		t.Errorf("other address must not be throttled, got %d", w.Code)
	}
}

func TestAuth_PasswordChangeSignsOutOtherSessions(t *testing.T) {
	h, dir := rawServer(t, nil)
	_ = auth.NewStore(dir).SetPassword("first passphrase", nil)
	a := &client{t: t, h: h, remote: "127.0.0.1:1"}
	b := &client{t: t, h: h, remote: "127.0.0.1:2"}
	a.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "first passphrase"})
	b.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "first passphrase"})

	if w := a.do(http.MethodPost, "/api/auth/password", map[string]interface{}{"current_password": "wrong one", "new_password": "second passphrase"}); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong current password: want 401, got %d", w.Code)
	}
	if w := a.do(http.MethodPost, "/api/auth/password", map[string]interface{}{"current_password": "first passphrase", "new_password": "second passphrase"}); w.Code != http.StatusOK {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if w := a.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusOK {
		t.Errorf("changing session must stay signed in, got %d", w.Code)
	}
	if w := b.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("other session must be signed out, got %d", w.Code)
	}
}

func TestAuth_CLIResetSignsOutSessions(t *testing.T) {
	h, dir := rawServer(t, nil)
	_ = auth.NewStore(dir).SetPassword("before reset", nil)
	c := &client{t: t, h: h, remote: "127.0.0.1:1"}
	c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "before reset"})

	// `proxygate passwd` runs in another process with its own store.
	if err := auth.NewStore(dir).SetPassword("after reset", nil); err != nil {
		t.Fatal(err)
	}
	if w := c.do(http.MethodGet, "/api/routes", nil); w.Code != http.StatusUnauthorized {
		t.Errorf("session must end after an external reset, got %d", w.Code)
	}
	if w := c.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "after reset"}); w.Code != http.StatusOK {
		t.Errorf("new password must work without restart, got %d", w.Code)
	}
}

func TestAuth_InsecureTransportReportedAndOptionallyRefused(t *testing.T) {
	h, dir := rawServer(t, nil)
	_ = auth.NewStore(dir).SetPassword("some passphrase", nil)

	var st map[string]interface{}
	remote := &client{t: t, h: h, remote: "192.0.2.10:1"}
	_ = json.Unmarshal(remote.do(http.MethodGet, "/api/auth/status", nil).Body.Bytes(), &st)
	if st["insecure_transport"] != true {
		t.Errorf("plain HTTP from the network must be flagged: %v", st)
	}
	local := &client{t: t, h: h, remote: "127.0.0.1:1"}
	_ = json.Unmarshal(local.do(http.MethodGet, "/api/auth/status", nil).Body.Bytes(), &st)
	if st["insecure_transport"] != false {
		t.Errorf("localhost must not be flagged: %v", st)
	}

	strict, sdir := rawServer(t, func(c *config.Config) { c.Security.RequireSecureLogin = true })
	_ = auth.NewStore(sdir).SetPassword("some passphrase", nil)
	r := &client{t: t, h: strict, remote: "192.0.2.10:1"}
	if w := r.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "some passphrase"}); w.Code != http.StatusForbidden {
		t.Errorf("require_secure_login: want 403 over plain HTTP, got %d", w.Code)
	}
	l := &client{t: t, h: strict, remote: "127.0.0.1:1"}
	if w := l.do(http.MethodPost, "/api/auth/login", map[string]interface{}{"password": "some passphrase"}); w.Code != http.StatusOK {
		t.Errorf("require_secure_login must allow localhost, got %d", w.Code)
	}
}
