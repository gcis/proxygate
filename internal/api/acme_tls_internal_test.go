package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/acmetest"
	"github.com/gcis/proxygate/internal/auth"
	"github.com/gcis/proxygate/internal/certmanager"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
	"github.com/gorilla/websocket"
)

type cfgAdapter struct{ m *config.Manager }

func (a cfgAdapter) Get() config.Config { return *a.m.Get() }

type internalEnv struct {
	srv     *Server
	cfg     *config.Manager
	token   string
	gdCalls atomic.Int32
	gdFail  atomic.Bool
}

// newInternalEnv wires a Server to a fake ACME CA and a fake GoDaddy API.
func newInternalEnv(t *testing.T, acmeDir string, mutate func(*config.Config)) *internalEnv {
	t.Helper()
	env := &internalEnv{}
	gd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.gdCalls.Add(1)
		if env.gdFail.Load() {
			http.Error(w, `{"code":"UNAVAILABLE","message":"down"}`, http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte("[]")) //nolint:errcheck
	}))
	t.Cleanup(gd.Close)

	dir := t.TempDir()
	cfgMgr, err := config.NewManager(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		_ = cfgMgr.Update(mutate)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	acmeClient, err := acme.NewClient("ops@example.com", filepath.Join(dir, "certs"), acmeDir, logger)
	if err != nil {
		t.Fatal(err)
	}
	engine := proxy.NewEngine(cfgMgr, logger)
	gdClient := godaddy.NewClient("k", "s", gd.URL, logger)
	certMgr := certmanager.NewManager(engine, nil, gdClient, cfgAdapter{cfgMgr}, logger)
	env.srv = NewServer(cfgMgr, engine, acmeClient, gdClient, certMgr, logger)
	env.srv.dnsPropagationWait = time.Millisecond
	env.cfg = cfgMgr
	env.token, err = auth.NewStore(dir).CreateToken("tests")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (e *internalEnv) do(t *testing.T, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.token)
	w := httptest.NewRecorder()
	e.srv.ServeHTTP(w, req)
	return w
}

func TestACMEThroughAPI_IssuesAndAttachesCertificate(t *testing.T) {
	ca := acmetest.New()
	defer ca.Close()
	env := newInternalEnv(t, ca.DirectoryURL(), nil)
	for _, prefix := range []string{"", "/api"} {
		if w := env.do(t, http.MethodPost, "/api/routes", map[string]interface{}{
			"domain": "app.example.com", "path_prefix": prefix, "target_host": "127.0.0.1", "target_port": 3000,
		}); w.Code != http.StatusCreated {
			t.Fatalf("create route: %d %s", w.Code, w.Body.String())
		}
	}

	w := env.do(t, http.MethodPost, "/api/acme/request", map[string]string{"domain": "App.Example.com"})
	var ch map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &ch)
	if w.Code != http.StatusOK || ch["record_name"] != "_acme-challenge.app.example.com" {
		t.Fatalf("request: %d %s", w.Code, w.Body.String())
	}

	w = env.do(t, http.MethodPost, "/api/acme/complete", map[string]interface{}{"domain": "app.example.com", "auto_dns": true})
	if w.Code != http.StatusOK {
		t.Fatalf("complete: %d %s", w.Code, w.Body.String())
	}
	if env.gdCalls.Load() == 0 {
		t.Error("auto_dns must publish the TXT record through GoDaddy")
	}
	for _, r := range env.cfg.Get().Routes {
		if !r.TLSEnabled || !r.AutoCert || r.CertFile == "" {
			t.Errorf("route %s%s not switched to TLS: %+v", r.Domain, r.PathPrefix, r)
		}
		if r.PathPrefix == "" && r.Domain != "app.example.com" {
			t.Errorf("unexpected route %+v", r)
		}
	}

	w = env.do(t, http.MethodGet, "/api/certs/status", nil)
	var st struct {
		Certs []struct {
			Domain        string `json:"domain"`
			DaysRemaining *int   `json:"days_remaining"`
			AutoRenew     bool   `json:"auto_renew"`
			Error         string `json:"error"`
		} `json:"certs"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &st)
	if len(st.Certs) != 1 || st.Certs[0].DaysRemaining == nil || *st.Certs[0].DaysRemaining < 80 || !st.Certs[0].AutoRenew {
		t.Errorf("certs status (one entry per domain, real expiry, renewable): %s", w.Body.String())
	}
}

func TestACMEThroughAPI_Failures(t *testing.T) {
	ca := acmetest.New()
	defer ca.Close()
	env := newInternalEnv(t, ca.DirectoryURL(), nil)

	if w := env.do(t, http.MethodPost, "/api/acme/request", map[string]string{"domain": "bad domain"}); w.Code != http.StatusBadRequest {
		t.Errorf("invalid domain: %d", w.Code)
	}

	env.do(t, http.MethodPost, "/api/acme/request", map[string]string{"domain": "x.example.com"})
	env.gdFail.Store(true)
	if w := env.do(t, http.MethodPost, "/api/acme/complete", map[string]interface{}{"domain": "x.example.com", "auto_dns": true}); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "auto DNS failed") {
		t.Errorf("GoDaddy failure: %d %s", w.Code, w.Body.String())
	}
	env.gdFail.Store(false)

	ca.FailValidation.Store(true)
	if w := env.do(t, http.MethodPost, "/api/acme/complete", map[string]interface{}{"domain": "x.example.com"}); w.Code != http.StatusInternalServerError {
		t.Errorf("validation failure: %d %s", w.Code, w.Body.String())
	}
}

func TestCertsStatus_UnreadableCertReported(t *testing.T) {
	env := newInternalEnv(t, "https://acme-staging-v02.api.letsencrypt.org/directory", func(c *config.Config) {
		c.Routes = []config.ProxyRoute{{ID: "r", Domain: "x.example.com", TLSEnabled: true, CertFile: "/nonexistent.pem", KeyFile: "/nonexistent.key", Enabled: true}}
	})
	w := env.do(t, http.MethodGet, "/api/certs/status", nil)
	if !strings.Contains(w.Body.String(), `"error"`) {
		t.Errorf("missing cert file must be reported per entry: %s", w.Body.String())
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

func waitHealthy(t *testing.T, url string, c *http.Client) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if resp, err := c.Get(url); err == nil {
			resp.Body.Close()
			return
		}
	}
	t.Fatalf("%s never answered", url)
}

func TestServe_PlainAndHTTPSShutDownCleanly(t *testing.T) {
	for _, tlsOn := range []bool{false, true} {
		env := newInternalEnv(t, "https://acme-staging-v02.api.letsencrypt.org/directory", nil)
		env.srv.security.AdminTLS.Enabled = tlsOn
		addr := freeAddr(t)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- env.srv.Serve(ctx, addr) }()

		scheme := "http"
		client := http.DefaultClient
		if tlsOn {
			scheme = "https"
			client = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}} //nolint:gosec // self-signed test cert
		}
		waitHealthy(t, scheme+"://"+addr+"/healthz", client)
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("tls=%v: Serve after cancel: %v", tlsOn, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("tls=%v: Serve did not stop", tlsOn)
		}
	}
}

func TestServe_ErrorsAreReturned(t *testing.T) {
	env := newInternalEnv(t, "https://acme-staging-v02.api.letsencrypt.org/directory", nil)
	if err := env.srv.Serve(context.Background(), "127.0.0.1:99999"); err == nil {
		t.Error("invalid address must fail")
	}
	env.srv.security.AdminTLS = config.AdminTLSConfig{Enabled: true, CertFile: "/nonexistent.crt", KeyFile: "/nonexistent.key"}
	if err := env.srv.Serve(context.Background(), freeAddr(t)); err == nil || !strings.Contains(err.Error(), "admin certificate") {
		t.Errorf("unreadable configured certificate: %v", err)
	}
}

func TestAdminTLSConfig_UsesConfiguredCertificate(t *testing.T) {
	env := newInternalEnv(t, "https://acme-staging-v02.api.letsencrypt.org/directory", nil)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "a.crt"), filepath.Join(dir, "a.key")
	if err := ensureSelfSigned(certFile, keyFile, "10.1.2.3"); err != nil {
		t.Fatal(err)
	}
	env.srv.security.AdminTLS = config.AdminTLSConfig{Enabled: true, CertFile: certFile, KeyFile: keyFile}
	cfg, fp, err := env.srv.adminTLSConfig()
	if err != nil || len(cfg.Certificates) != 1 || strings.Count(fp, ":") != 31 {
		t.Fatalf("configured cert: %v %q", err, fp)
	}

	// A generated certificate cannot be written into a missing directory tree
	// rooted at a file.
	env.srv.security.AdminTLS = config.AdminTLSConfig{Enabled: true}
	env.srv.dataDir = filepath.Join(certFile, "sub")
	if _, _, err := env.srv.adminTLSConfig(); err == nil || !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("unwritable data dir: %v", err)
	}
}

func TestEnsureSelfSigned_RegeneratesInvalidOrMissingKey(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")
	if err := ensureSelfSigned(certFile, keyFile, ""); err != nil {
		t.Fatal(err)
	}
	if err := ensureSelfSigned(certFile, filepath.Join(dir, "missing.key"), ""); err != nil {
		t.Errorf("missing key must trigger regeneration: %v", err)
	}
	if err := ensureSelfSigned(filepath.Join(certFile, "x"), keyFile, "localhost"); err == nil {
		t.Error("unwritable location must fail")
	}
}

func TestInternalHelpers(t *testing.T) {
	cases := map[time.Duration]string{168 * time.Hour: "7d", 12 * time.Hour: "12h", 90 * time.Minute: "1h30m0s"}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", d, got, want)
		}
	}
	if got := colonHex([]byte{0xab, 0x01}); got != "AB:01" {
		t.Errorf("colonHex: %q", got)
	}
	if badRequest("x %d", 1).Error() != "x 1" {
		t.Error("badRequestError.Error")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.7" // no port
	if ip := clientIP(r); ip == nil || ip.String() != "10.0.0.7" {
		t.Errorf("clientIP without port: %v", ip)
	}
	r.RemoteAddr = "not-an-ip"
	if got := clientKey(r); got != "not-an-ip" {
		t.Errorf("clientKey fallback: %q", got)
	}

	rl := NewRateLimiter(1, time.Millisecond)
	rl.Allow("1.2.3.4")
	time.Sleep(5 * time.Millisecond)
	rl.cleanup()
	rl.mu.Lock()
	left := len(rl.visitors)
	rl.mu.Unlock()
	if left != 0 {
		t.Errorf("cleanup kept %d stale visitors", left)
	}
}

func TestWSHub_BroadcastReachesConnectedClient(t *testing.T) {
	hub := NewWSHub(slog.New(slog.NewTextHandler(io.Discard, nil)))
	ts := httptest.NewServer(http.HandlerFunc(hub.HandleWS))
	defer ts.Close()
	conn := dialWS(t, ts.URL)

	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		hub.mu.RLock()
		n := len(hub.clients)
		hub.mu.RUnlock()
		if n == 1 {
			break
		}
	}
	hub.Broadcast(WSMessage{Type: "route_added", Payload: map[string]string{"id": "r1"}})
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var msg WSMessage
	if err := conn.ReadJSON(&msg); err != nil || msg.Type != "route_added" {
		t.Fatalf("broadcast not received: %v %+v", err, msg)
	}

	conn.Close()
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		hub.Broadcast(WSMessage{Type: "ping"})
		hub.mu.RLock()
		n := len(hub.clients)
		hub.mu.RUnlock()
		if n == 0 {
			return
		}
	}
	t.Error("closed client was never removed")
}

func dialWS(t *testing.T, httpURL string) *websocket.Conn {
	t.Helper()
	wsURL := "ws" + strings.TrimPrefix(httpURL, "http")
	conn, _, err := websocket.DefaultDialer.Dial(wsURL, http.Header{"Origin": []string{httpURL}})
	if err != nil {
		t.Fatal(err)
	}
	return conn
}
