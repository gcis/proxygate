package api_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/api"
)

// ─── SecurityHeaders ──────────────────────────────────────────────────────────

func TestSecurityHeaders_SetsRequiredHeaders(t *testing.T) {
	handler := api.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"X-Xss-Protection":       "1; mode=block",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, val := range want {
		if got := w.Header().Get(header); got != val {
			t.Errorf("%s: want %q, got %q", header, val, got)
		}
	}
	if csp := w.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header is missing")
	}
}

func TestSecurityHeaders_CallsNextHandler(t *testing.T) {
	called := false
	handler := api.SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if !called {
		t.Error("SecurityHeaders did not call next handler")
	}
	if w.Code != http.StatusTeapot {
		t.Errorf("status: want 418, got %d", w.Code)
	}
}

// ─── NetworkWhitelist ─────────────────────────────────────────────────────────

func makeRequest(remoteAddr string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	return req
}

func TestNetworkWhitelist_AllowsLocalhostByDefault(t *testing.T) {
	// Empty allowed list → falls back to loopback only.
	handler := api.NetworkWhitelist(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	for _, addr := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		req := makeRequest(addr)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("addr %s: want 200, got %d", addr, w.Code)
		}
	}
}

func TestNetworkWhitelist_BlocksExternalIP(t *testing.T) {
	handler := api.NetworkWhitelist(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := makeRequest("203.0.113.42:9999") // TEST-NET, not loopback
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("external IP: want 403, got %d", w.Code)
	}
}

func TestNetworkWhitelist_AllowsConfiguredCIDR(t *testing.T) {
	handler := api.NetworkWhitelist([]string{"10.0.0.0/8"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("allowed", func(t *testing.T) {
		req := makeRequest("10.1.2.3:1234")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("10.1.2.3 in 10.0.0.0/8: want 200, got %d", w.Code)
		}
	})

	t.Run("blocked", func(t *testing.T) {
		req := makeRequest("192.168.1.1:1234")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("192.168.1.1 not in 10.0.0.0/8: want 403, got %d", w.Code)
		}
	})
}

func TestNetworkWhitelist_AllowsPlainIPAddress(t *testing.T) {
	// Plain IP (no CIDR) should be accepted as a /32.
	handler := api.NetworkWhitelist([]string{"203.0.113.5"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := makeRequest("203.0.113.5:4567")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("exact IP: want 200, got %d", w.Code)
	}

	// A different IP in the same /24 must still be blocked.
	req2 := makeRequest("203.0.113.6:4567")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusForbidden {
		t.Errorf("adjacent IP: want 403, got %d", w2.Code)
	}
}

func TestNetworkWhitelist_FallsBackToLocalhostForInvalidNetworks(t *testing.T) {
	// All entries are invalid CIDR/IP → falls back to localhost only.
	handler := api.NetworkWhitelist([]string{"not-an-ip", "999.999.999.999/99"})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := makeRequest("127.0.0.1:1234")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("localhost after fallback: want 200, got %d", w.Code)
	}
}

// ─── RateLimiter ──────────────────────────────────────────────────────────────

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := api.NewRateLimiter(3, time.Minute)

	for i := 1; i <= 3; i++ {
		if !rl.Allow("10.0.0.1") {
			t.Errorf("request %d: want allowed (limit=3), got blocked", i)
		}
	}
}

func TestRateLimiter_BlocksOverLimit(t *testing.T) {
	rl := api.NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		rl.Allow("10.0.0.1") //nolint:errcheck
	}
	if rl.Allow("10.0.0.1") {
		t.Error("4th request: want blocked, got allowed")
	}
}

func TestRateLimiter_IndependentPerIP(t *testing.T) {
	rl := api.NewRateLimiter(1, time.Minute)
	rl.Allow("10.0.0.1") //nolint:errcheck — exhausted

	// Different IP should still be allowed.
	if !rl.Allow("10.0.0.2") {
		t.Error("different IP should not be rate-limited by other IP's counter")
	}
}

func TestRateLimiter_ResetsAfterWindow(t *testing.T) {
	// Use a very short window so we can actually test expiry without sleeping too long.
	rl := api.NewRateLimiter(1, 50*time.Millisecond)
	rl.Allow("10.0.0.1") //nolint:errcheck — exhausted
	if rl.Allow("10.0.0.1") {
		t.Fatal("immediately after limit: want blocked, got allowed")
	}

	time.Sleep(60 * time.Millisecond) // let the window expire

	if !rl.Allow("10.0.0.1") {
		t.Error("after window reset: want allowed, got blocked")
	}
}

// ─── RateLimit middleware ─────────────────────────────────────────────────────

func TestRateLimit_Middleware_Returns429WhenExceeded(t *testing.T) {
	rl := api.NewRateLimiter(1, time.Minute)
	handler := api.RateLimit(rl)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request: OK
	req1 := makeRequest("10.0.0.1:1234")
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Errorf("first request: want 200, got %d", w1.Code)
	}

	// Second request: rate-limited
	req2 := makeRequest("10.0.0.1:1234")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Errorf("second request: want 429, got %d", w2.Code)
	}
}

// ─── Chain ────────────────────────────────────────────────────────────────────

func TestChain_AppliesMiddlewaresInOrder(t *testing.T) {
	var order []string

	mid := func(label string) func(http.Handler) http.Handler {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, label)
				next.ServeHTTP(w, r)
			})
		}
	}

	handler := api.Chain(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { order = append(order, "inner") }),
		mid("A"),
		mid("B"),
		mid("C"),
	)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))

	want := []string{"A", "B", "C", "inner"}
	if len(order) != len(want) {
		t.Fatalf("chain order: want %v, got %v", want, order)
	}
	for i, v := range want {
		if order[i] != v {
			t.Errorf("chain order[%d]: want %s, got %s", i, v, order[i])
		}
	}
}
