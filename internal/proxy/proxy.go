// Package proxy implements the core reverse proxy engine with dynamic routing and TLS.
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gcis/proxygate/internal/config"
)

type Engine struct {
	mu         sync.RWMutex
	// routes is a flat slice of enabled routes, sorted so that longer
	// PathPrefixes come first (most-specific wins).
	routes     []*config.ProxyRoute
	tlsCerts   map[string]*tls.Certificate
	httpServer *http.Server
	tlsServer  *http.Server
	logger     *slog.Logger
	configMgr  *config.Manager
}

func NewEngine(cfgMgr *config.Manager, logger *slog.Logger) *Engine {
	e := &Engine{
		tlsCerts:  make(map[string]*tls.Certificate),
		logger:    logger,
		configMgr: cfgMgr,
	}

	e.loadRoutes(cfgMgr.Get())
	cfgMgr.OnChange(func(cfg *config.Config) {
		e.loadRoutes(cfg)
		e.logger.Info("proxy routes reloaded", "count", len(cfg.Routes))
	})

	return e
}

func (e *Engine) loadRoutes(cfg *config.Config) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Collect enabled routes, sorted longest PathPrefix first so that
	// more-specific routes (e.g. "/mqtt") win over catch-alls ("").
	var newRoutes []*config.ProxyRoute
	for i := range cfg.Routes {
		r := cfg.Routes[i]
		if r.Enabled {
			rc := r
			newRoutes = append(newRoutes, &rc)
		}
	}
	// Stable sort: longer PathPrefix → higher priority.
	for i := 1; i < len(newRoutes); i++ {
		for j := i; j > 0 && len(newRoutes[j].PathPrefix) > len(newRoutes[j-1].PathPrefix); j-- {
			newRoutes[j], newRoutes[j-1] = newRoutes[j-1], newRoutes[j]
		}
	}
	e.routes = newRoutes

	// Load TLS certificates
	newCerts := make(map[string]*tls.Certificate)
	for _, route := range newRoutes {
		if route.TLSEnabled && route.CertFile != "" && route.KeyFile != "" {
			if _, already := newCerts[route.Domain]; already {
				continue
			}
			cert, err := tls.LoadX509KeyPair(route.CertFile, route.KeyFile)
			if err != nil {
				e.logger.Error("failed to load TLS cert", "domain", route.Domain, "error", err)
				continue
			}
			newCerts[route.Domain] = &cert
			e.logger.Info("loaded TLS certificate", "domain", route.Domain)
		}
	}
	e.tlsCerts = newCerts
}

func (e *Engine) LoadCertificate(domain, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("loading certificate for %s: %w", domain, err)
	}

	e.mu.Lock()
	e.tlsCerts[domain] = &cert
	e.mu.Unlock()

	e.logger.Info("loaded TLS certificate", "domain", domain)
	return nil
}

func (e *Engine) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if cert, ok := e.tlsCerts[hello.ServerName]; ok {
		return cert, nil
	}
	return nil, fmt.Errorf("no certificate for %s", hello.ServerName)
}

// matchRoute returns the best-matching enabled route for the given host and
// request path.  Routes with a PathPrefix are preferred over catch-alls; ties
// are broken by the order they appear in e.routes (longest prefix first).
func (e *Engine) matchRoute(host, path string) *config.ProxyRoute {
	for _, r := range e.routes {
		if r.Domain != host {
			continue
		}
		if r.PathPrefix == "" || strings.HasPrefix(path, r.PathPrefix) {
			return r
		}
	}
	return nil
}

func (e *Engine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}

	e.mu.RLock()
	route := e.matchRoute(host, r.URL.Path)
	e.mu.RUnlock()

	if route == nil {
		e.logger.Warn("no route found", "host", host, "path", r.URL.Path, "remote", r.RemoteAddr)
		http.Error(w, "502 Bad Gateway - No route configured for this host", http.StatusBadGateway)
		return
	}

	// Redirect HTTP to HTTPS if TLS is enabled
	if route.TLSEnabled && r.TLS == nil {
		target := "https://" + r.Host + r.URL.RequestURI()
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return
	}

	targetURL := &url.URL{
		Scheme: "http",
		Host:   fmt.Sprintf("%s:%d", route.TargetHost, route.TargetPort),
	}

	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.FlushInterval = -1 // Stream immediately (required for WebSocket/SSE)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		e.logger.Error("proxy error", "domain", route.Domain, "target", targetURL.String(), "error", err)
		http.Error(w, "502 Bad Gateway - Target unreachable", http.StatusBadGateway)
	}

	// Preserve original headers
	isUpgrade := r.Header.Get("Upgrade") != ""
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Set("X-Forwarded-For", r.RemoteAddr)
		req.Header.Set("X-Forwarded-Host", host)
		req.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
		if r.TLS != nil {
			req.Header.Set("X-Forwarded-Proto", "https")
		}
		req.Host = r.Host
	}

	if isUpgrade {
		e.logger.Info("proxying websocket",
			"domain", host,
			"target", targetURL.String(),
			"path", r.URL.Path,
		)
	} else {
		e.logger.Info("proxying request",
			"domain", host,
			"target", targetURL.String(),
			"method", r.Method,
			"path", r.URL.Path,
		)
	}

	proxy.ServeHTTP(w, r)
}

func (e *Engine) Start(cfg *config.Config) error {
	e.httpServer = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Server.HTTPPort),
		Handler:           e,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Start HTTP server
	go func() {
		e.logger.Info("starting HTTP proxy", "port", cfg.Server.HTTPPort)
		if err := e.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			e.logger.Error("HTTP server error", "error", err)
		}
	}()

	// Start HTTPS server if any routes have TLS
	hasTLS := false
	for _, route := range cfg.Routes {
		if route.TLSEnabled && route.Enabled {
			hasTLS = true
			break
		}
	}

	if hasTLS {
		tlsConfig := &tls.Config{
			GetCertificate: e.getCertificate,
			MinVersion:     tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		}

		e.tlsServer = &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.Server.HTTPSPort),
			Handler:           e,
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
		}

		go func() {
			e.logger.Info("starting HTTPS proxy", "port", cfg.Server.HTTPSPort)
			if err := e.tlsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				e.logger.Error("HTTPS server error", "error", err)
			}
		}()
	}

	return nil
}

func (e *Engine) Stop(ctx context.Context) error {
	var errs []error

	if e.httpServer != nil {
		if err := e.httpServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTP shutdown: %w", err))
		}
	}

	if e.tlsServer != nil {
		if err := e.tlsServer.Shutdown(ctx); err != nil {
			errs = append(errs, fmt.Errorf("HTTPS shutdown: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("shutdown errors: %v", errs)
	}
	return nil
}

func (e *Engine) GetRouteStatus() []RouteStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var statuses []RouteStatus
	for _, route := range e.routes {
		status := RouteStatus{
			Domain:  route.Domain,
			Route:   *route,
			Active:  true,
			HasCert: e.tlsCerts[route.Domain] != nil,
		}
		statuses = append(statuses, status)
	}
	return statuses
}

type RouteStatus struct {
	Domain  string            `json:"domain"`
	Route   config.ProxyRoute `json:"route"`
	Active  bool              `json:"active"`
	HasCert bool              `json:"has_cert"`
}
