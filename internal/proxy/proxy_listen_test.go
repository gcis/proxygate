package proxy_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/proxy"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuf) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func waitListening(t *testing.T, port int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond); err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %d", port)
}

// TestEngine_ListenersEndToEnd drives the real HTTP and HTTPS listeners.
func TestEngine_ListenersEndToEnd(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "backend:"+r.Host+r.URL.Path) //nolint:errcheck
	}))
	defer backend.Close()
	bport := backendPort(t, backend)
	certFile, keyFile := generateTestCert(t) // CN test.example.com

	mgr, err := config.NewManager(t.TempDir() + "/config.json")
	if err != nil {
		t.Fatal(err)
	}
	httpPort, httpsPort := freePort(t), freePort(t)
	_ = mgr.Update(func(c *config.Config) {
		c.Server.HTTPPort, c.Server.HTTPSPort = httpPort, httpsPort
		c.Routes = []config.ProxyRoute{
			{ID: "plain", Domain: "plain.test", TargetHost: "127.0.0.1", TargetPort: bport, Enabled: true},
			{ID: "tls", Domain: "test.example.com", TargetHost: "127.0.0.1", TargetPort: bport, Enabled: true,
				TLSEnabled: true, CertFile: certFile, KeyFile: keyFile},
			// A TLS route whose files are missing is skipped, not fatal.
			{ID: "broken", Domain: "broken.test", TargetHost: "127.0.0.1", TargetPort: bport, Enabled: true,
				TLSEnabled: true, CertFile: "/nonexistent.pem", KeyFile: "/nonexistent.key"},
			// Two routes on one domain share a certificate (loaded once).
			{ID: "tls-api", Domain: "test.example.com", PathPrefix: "/api", TargetHost: "127.0.0.1", TargetPort: bport, Enabled: true,
				TLSEnabled: true, CertFile: certFile, KeyFile: keyFile},
		}
	})

	logs := &lockedBuf{}
	engine := proxy.NewEngine(mgr, slog.New(slog.NewTextHandler(logs, nil)))
	if err := engine.Start(mgr.Get()); err != nil {
		t.Fatal(err)
	}
	waitListening(t, httpPort)
	waitListening(t, httpsPort)
	if !strings.Contains(logs.String(), "failed to load TLS cert") {
		t.Error("missing certificate files must be reported")
	}

	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/hello", nil)
	req.Host = "plain.test"
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "backend:plain.test/hello" {
		t.Errorf("plain HTTP route: %q", body)
	}

	req.Host = "test.example.com"
	resp, err = noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently || !strings.HasPrefix(resp.Header.Get("Location"), "https://test.example.com") {
		t.Errorf("TLS route over HTTP must redirect: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// HTTPS: the certificate is chosen by SNI.
	pemData, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(pemData)
	caCert, _ := x509.ParseCertificate(block.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	httpsClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "test.example.com"}}}
	req, _ = http.NewRequest(http.MethodGet, "https://127.0.0.1:"+strconv.Itoa(httpsPort)+"/secure", nil)
	req.Host = "test.example.com"
	resp, err = httpsClient.Do(req)
	if err != nil {
		t.Fatalf("HTTPS request: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "backend:test.example.com/secure" {
		t.Errorf("HTTPS route: %q", body)
	}

	// An unknown server name gets no certificate: the handshake fails.
	conn, err := tls.Dial("tcp", "127.0.0.1:"+strconv.Itoa(httpsPort), &tls.Config{ServerName: "unknown.test", InsecureSkipVerify: true}) //nolint:gosec // testing the server side
	if err == nil {
		conn.Close()
		t.Error("handshake for an unknown name must fail")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := engine.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(httpPort), 200*time.Millisecond); err == nil {
		c.Close()
		t.Error("HTTP listener still open after Stop")
	}
}

func TestEngine_BusyPortsAreLoggedNotFatal(t *testing.T) {
	busy, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port

	mgr, _ := config.NewManager(t.TempDir() + "/config.json")
	_ = mgr.Update(func(c *config.Config) { c.Server.HTTPPort, c.Server.HTTPSPort = port, port })
	logs := &lockedBuf{}
	engine := proxy.NewEngine(mgr, slog.New(slog.NewTextHandler(logs, nil)))
	if err := engine.Start(mgr.Get()); err != nil {
		t.Fatalf("Start must not fail on a busy port: %v", err)
	}
	engine.EnsureHTTPSStarted()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !(strings.Contains(logs.String(), "HTTP server error") && strings.Contains(logs.String(), "HTTPS server error")) {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(logs.String(), "HTTP server error") || !strings.Contains(logs.String(), "HTTPS server error") {
		t.Errorf("bind failures not logged: %s", logs.String())
	}
	_ = engine.Stop(context.Background())
}

func TestEngine_StopTimesOutWithOpenConnection(t *testing.T) {
	// A hijacked-style slow request keeps Shutdown waiting; an expired
	// context makes Stop report it instead of hanging.
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer backend.Close()
	defer close(release)

	mgr, _ := config.NewManager(t.TempDir() + "/config.json")
	httpPort := freePort(t)
	_ = mgr.Update(func(c *config.Config) {
		c.Server.HTTPPort, c.Server.HTTPSPort = httpPort, freePort(t)
		c.Routes = []config.ProxyRoute{{ID: "slow", Domain: "slow.test", TargetHost: "127.0.0.1", TargetPort: backendPort(t, backend), Enabled: true}}
	})
	engine := proxy.NewEngine(mgr, silentLogger())
	_ = engine.Start(mgr.Get())
	engine.EnsureHTTPSStarted()
	waitListening(t, httpPort)

	go func() {
		req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(httpPort)+"/", nil)
		req.Host = "slow.test"
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(200 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := engine.Stop(ctx); err == nil || !strings.Contains(err.Error(), "shutdown") {
		t.Errorf("Stop with an in-flight request and expired context: %v", err)
	}
}
