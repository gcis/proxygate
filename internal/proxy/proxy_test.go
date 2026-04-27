package proxy_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/proxy"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// newTestEngine creates a Manager + Engine wired to a temp config file.
func newTestEngine(t *testing.T, routes []config.ProxyRoute) (*proxy.Engine, *config.Manager) {
	t.Helper()
	mgr, err := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("config.NewManager: %v", err)
	}
	for _, r := range routes {
		if err := mgr.AddRoute(r); err != nil {
			t.Fatalf("AddRoute: %v", err)
		}
	}
	return proxy.NewEngine(mgr, silentLogger()), mgr
}

// backendPort parses the port from an httptest.Server URL.
func backendPort(t *testing.T, s *httptest.Server) int {
	t.Helper()
	u, err := url.Parse(s.URL)
	if err != nil {
		t.Fatalf("parse backend URL: %v", err)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse backend port: %v", err)
	}
	return port
}

// ─── No-route (502) ───────────────────────────────────────────────────────────

func TestServeHTTP_NoRoute_Returns502(t *testing.T) {
	engine, _ := newTestEngine(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "unknown.example.com"
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("want 502, got %d", w.Code)
	}
}

func TestServeHTTP_DisabledRoute_Returns502(t *testing.T) {
	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{ID: "r1", Domain: "example.com", TargetHost: "localhost", TargetPort: 3000, Enabled: false},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "example.com"
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code != http.StatusBadGateway {
		t.Errorf("disabled route should produce 502, got %d", w.Code)
	}
}

// ─── HTTP → HTTPS redirect ────────────────────────────────────────────────────

func TestServeHTTP_TLSRoute_RedirectsHTTPToHTTPS(t *testing.T) {
	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{ID: "r1", Domain: "secure.example.com", TargetHost: "localhost", TargetPort: 3000, TLSEnabled: true, Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/page?q=1", nil)
	req.Host = "secure.example.com"
	// req.TLS is nil → plain HTTP
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code != http.StatusMovedPermanently {
		t.Errorf("want 301, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://secure.example.com") {
		t.Errorf("redirect Location should start with https://secure.example.com, got %q", loc)
	}
	if !strings.Contains(loc, "/page?q=1") {
		t.Errorf("redirect Location should preserve path and query, got %q", loc)
	}
}

// ─── Proxy forwarding ─────────────────────────────────────────────────────────

func TestServeHTTP_ProxiesRequestToBackend(t *testing.T) {
	received := make(chan *http.Request, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Clone(r.Context())
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{ID: "r1", Domain: "app.example.com", TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Host = "app.example.com"
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	select {
	case r := <-received:
		if r.URL.Path != "/api/data" {
			t.Errorf("backend got path %q, want /api/data", r.URL.Path)
		}
	default:
		t.Error("backend did not receive a request")
	}
}

func TestServeHTTP_SetsXForwardedHeaders(t *testing.T) {
	headers := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{ID: "r1", Domain: "app.example.com", TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: true},
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "app.example.com"
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	select {
	case h := <-headers:
		if h.Get("X-Forwarded-Host") == "" {
			t.Error("X-Forwarded-Host not set on proxied request")
		}
		if h.Get("X-Forwarded-For") == "" {
			t.Error("X-Forwarded-For not set on proxied request")
		}
	default:
		t.Error("backend did not receive a request")
	}
}

// ─── Path-prefix routing ──────────────────────────────────────────────────────

func TestServeHTTP_PathPrefixRouting_LongerPrefixWins(t *testing.T) {
	hitCh := make(chan string, 2)

	backendSpecific := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- "specific"
		w.WriteHeader(http.StatusOK)
	}))
	defer backendSpecific.Close()

	backendCatchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hitCh <- "catchall"
		w.WriteHeader(http.StatusOK)
	}))
	defer backendCatchAll.Close()

	// Catch-all route (empty PathPrefix) must be registered first so we can
	// verify the engine sorts by prefix length, not insertion order.
	engine, mgr := newTestEngine(t, nil)
	mgr.AddRoute(config.ProxyRoute{ //nolint:errcheck
		ID: "catchall", Domain: "multi.example.com", PathPrefix: "",
		TargetHost: "127.0.0.1", TargetPort: backendPort(t, backendCatchAll), Enabled: true,
	})
	mgr.AddRoute(config.ProxyRoute{ //nolint:errcheck
		ID: "specific", Domain: "multi.example.com", PathPrefix: "/api",
		TargetHost: "127.0.0.1", TargetPort: backendPort(t, backendSpecific), Enabled: true,
	})
	_ = engine // engine is updated via OnChange listener

	// Re-create engine from the updated manager so routes are loaded.
	eng := proxy.NewEngine(mgr, silentLogger())

	t.Run("api path hits specific backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
		req.Host = "multi.example.com"
		eng.ServeHTTP(httptest.NewRecorder(), req)

		select {
		case which := <-hitCh:
			if which != "specific" {
				t.Errorf("want specific backend, got %s backend", which)
			}
		default:
			t.Error("no backend received the request")
		}
	})

	t.Run("non-api path hits catch-all backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/home", nil)
		req.Host = "multi.example.com"
		eng.ServeHTTP(httptest.NewRecorder(), req)

		select {
		case which := <-hitCh:
			if which != "catchall" {
				t.Errorf("want catchall backend, got %s backend", which)
			}
		default:
			t.Error("no backend received the request")
		}
	})
}

// ─── GetRouteStatus ───────────────────────────────────────────────────────────

func TestGetRouteStatus_ReturnsEnabledRoutes(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{ID: "r1", Domain: "a.com", TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: true},
		{ID: "r2", Domain: "b.com", TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: false}, // disabled
	})

	statuses := engine.GetRouteStatus()

	if len(statuses) != 1 {
		t.Fatalf("expected 1 active route status, got %d", len(statuses))
	}
	if statuses[0].Domain != "a.com" {
		t.Errorf("Domain: want a.com, got %s", statuses[0].Domain)
	}
	if !statuses[0].Active {
		t.Error("Active should be true for enabled route")
	}
}

// ─── Hot reload ───────────────────────────────────────────────────────────────

func TestHotReload_NewRouteServedAfterConfigChange(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()

	engine, mgr := newTestEngine(t, nil)

	// Initially: unknown host → 502
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "new.example.com"
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Code != http.StatusBadGateway {
		t.Fatalf("pre-reload: want 502, got %d", w.Code)
	}

	// Add route — the OnChange listener wired in NewEngine reloads routes.
	mgr.AddRoute(config.ProxyRoute{ //nolint:errcheck
		ID: "new", Domain: "new.example.com",
		TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: true,
	})

	// Now the same request should reach the backend (204).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Host = "new.example.com"
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Errorf("post-reload: want 204, got %d", w2.Code)
	}
}

// ─── Integration: full HTTP proxy round-trip ─────────────────────────────────

// TestIntegration_ProxyRoundTrip exercises the complete path: incoming HTTP
// request → proxy engine → backend server → response back to client.
func TestIntegration_ProxyRoundTrip(t *testing.T) {
	const responseBody = "hello from backend"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Backend", "true")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(responseBody)) //nolint:errcheck
	}))
	defer backend.Close()

	engine, _ := newTestEngine(t, []config.ProxyRoute{
		{
			ID:         "integration",
			Name:       "Integration Test Route",
			Domain:     "integration.test",
			TargetHost: "127.0.0.1",
			TargetPort: backendPort(t, backend),
			Enabled:    true,
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	req.Host = "integration.test"
	req.RemoteAddr = "127.0.0.1:54321"
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status: want 200, got %d", w.Code)
	}
	if body := w.Body.String(); body != responseBody {
		t.Errorf("body: want %q, got %q", responseBody, body)
	}
	if w.Header().Get("X-Backend") != "true" {
		t.Error("backend response header X-Backend not forwarded")
	}
}
