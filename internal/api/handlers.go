package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/gcis/proxygate/docs"
	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/auth"
	"github.com/gcis/proxygate/internal/certmanager"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

const (
	// RateLimitRequests and RateLimitWindow bound admin API traffic per client IP.
	RateLimitRequests = 1000
	RateLimitWindow   = time.Minute

	maxBodyBytes = 256 << 10 // 256 KiB is far above any legitimate admin payload
	maskedSecret = "********"
)

var routeIDRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

type Server struct {
	configMgr     *config.Manager
	engine        *proxy.Engine
	acmeClient    *acme.Client
	godaddyClient *godaddy.Client
	certMgr       *certmanager.Manager
	wsHub         *WSHub
	logger        *slog.Logger
	mux           *http.ServeMux

	// Admin authentication (always on; see docs/security.md).
	authStore    *auth.Store
	sessions     *auth.Sessions
	loginLimiter *auth.LoginLimiter
	hashSlots    chan struct{}
	security     config.SecurityConfig
	dataDir      string
}

func NewServer(
	cfgMgr *config.Manager,
	engine *proxy.Engine,
	acmeClient *acme.Client,
	godaddyClient *godaddy.Client,
	certMgr *certmanager.Manager,
	logger *slog.Logger,
) *Server {
	s := &Server{
		configMgr:     cfgMgr,
		engine:        engine,
		acmeClient:    acmeClient,
		godaddyClient: godaddyClient,
		certMgr:       certMgr,
		wsHub:         NewWSHub(logger),
		logger:        logger,
		mux:           http.NewServeMux(),
	}

	// Auth state lives next to the config file. Security settings are read
	// once: they take effect at startup, like the listener settings.
	s.dataDir = cfgMgr.Dir()
	s.security = cfgMgr.Get().Security
	s.authStore = auth.NewStore(s.dataDir)
	s.sessions = auth.NewSessions(s.security.SessionIdle(), s.security.SessionMax())
	s.loginLimiter = auth.NewLoginLimiter(loginMaxFailures, loginWindow)
	s.hashSlots = make(chan struct{}, maxConcurrentHashes)

	s.registerRoutes()

	// Notify UI on config changes. Never broadcast the GoDaddy secret.
	cfgMgr.OnChange(func(cfg *config.Config) {
		s.wsHub.Broadcast(WSMessage{Type: "config_changed", Payload: redactConfig(cfg)})
	})

	return s
}

func (s *Server) registerRoutes() {
	// Authentication
	s.mux.HandleFunc("GET /api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("POST /api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("POST /api/auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /api/auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("POST /api/auth/password", s.handleAuthChangePassword)

	// API routes
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config/server", s.handleUpdateServerConfig)
	s.mux.HandleFunc("GET /api/security/status", s.handleSecurityStatus)

	// Routes CRUD
	s.mux.HandleFunc("GET /api/routes", s.handleListRoutes)
	s.mux.HandleFunc("POST /api/routes", s.handleCreateRoute)
	s.mux.HandleFunc("GET /api/routes/{id}", s.handleGetRoute)
	s.mux.HandleFunc("PUT /api/routes/{id}", s.handleUpdateRoute)
	s.mux.HandleFunc("PATCH /api/routes/{id}/toggle", s.handleToggleRoute)
	s.mux.HandleFunc("DELETE /api/routes/{id}", s.handleDeleteRoute)

	// Proxy status
	s.mux.HandleFunc("GET /api/status", s.handleStatus)

	// ACME / Let's Encrypt
	s.mux.HandleFunc("POST /api/acme/request", s.handleACMERequest)
	s.mux.HandleFunc("POST /api/acme/complete", s.handleACMEComplete)
	s.mux.HandleFunc("GET /api/acme/challenges", s.handleACMEChallenges)
	s.mux.HandleFunc("PUT /api/acme/config", s.handleUpdateACMEConfig)

	// GoDaddy DNS
	s.mux.HandleFunc("PUT /api/godaddy/config", s.handleUpdateGoDaddyConfig)
	s.mux.HandleFunc("POST /api/godaddy/verify", s.handleVerifyGoDaddy)
	s.mux.HandleFunc("GET /api/godaddy/domains", s.handleListGoDaddyDomains)
	s.mux.HandleFunc("GET /api/godaddy/domains/{domain}/records", s.handleListDNSRecords)
	s.mux.HandleFunc("POST /api/godaddy/domains/{domain}/records", s.handleCreateDNSRecord)
	s.mux.HandleFunc("DELETE /api/godaddy/domains/{domain}/records/{type}/{name}", s.handleDeleteDNSRecord)
	s.mux.HandleFunc("POST /api/godaddy/auto-dns", s.handleAutoDNS)

	// Certificate status
	s.mux.HandleFunc("GET /api/certs/status", s.handleCertsStatus)

	// Health check (for load balancers and k8s probes)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// WebSocket
	s.mux.HandleFunc("GET /ws", s.wsHub.HandleWS)

	// Embedded documentation site
	docsFS, err := fs.Sub(docs.FS, ".")
	if err == nil {
		s.mux.Handle("GET /docs/", http.StripPrefix("/docs/", http.FileServer(http.FS(docsFS))))
		s.mux.Handle("GET /docs", http.RedirectHandler("/docs/", http.StatusMovedPermanently))
	}

	// Static UI files
	s.mux.HandleFunc("GET /", s.handleUI)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS: only ever reflect our own origin, never "*". Combined with the
	// cross-origin write check below this blocks CSRF from other sites the
	// operator has open in the same browser.
	if origin := r.Header.Get("Origin"); origin != "" {
		if !sameOrigin(r) {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				jsonError(w, http.StatusForbidden, "cross-origin request rejected")
				return
			}
		} else {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		}
	}

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if requiresAuth(r.URL.Path) && !s.authenticated(r) {
		w.Header().Set("Cache-Control", "no-store")
		jsonError(w, http.StatusUnauthorized, "authentication required")
		return
	}

	s.mux.ServeHTTP(w, r)
}

// sameOrigin reports whether the request's Origin header names this server
// (matching Host, or X-Forwarded-Host when behind another proxy).
func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	o := strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://")
	if o == origin { // not an http(s) origin, e.g. "null"
		return false
	}
	if strings.EqualFold(o, r.Host) {
		return true
	}
	if fh := r.Header.Get("X-Forwarded-Host"); fh != "" && strings.EqualFold(o, strings.TrimSpace(strings.Split(fh, ",")[0])) {
		return true
	}
	return false
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// badRequestError marks a validation failure raised inside a config update.
type badRequestError struct{ msg string }

func (e badRequestError) Error() string { return e.msg }

func badRequest(format string, args ...any) error {
	return badRequestError{msg: fmt.Sprintf(format, args...)}
}

// writeUpdateError maps config/validation errors onto HTTP status codes.
func writeUpdateError(w http.ResponseWriter, err error) {
	var br badRequestError
	switch {
	case errors.As(err, &br):
		jsonError(w, http.StatusBadRequest, br.msg)
	case errors.Is(err, config.ErrRouteNotFound):
		jsonError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, config.ErrRouteConflict):
		jsonError(w, http.StatusConflict, err.Error())
	default:
		jsonError(w, http.StatusInternalServerError, err.Error())
	}
}

func redactConfig(cfg *config.Config) config.Config {
	cp := *cfg
	cp.Routes = append([]config.ProxyRoute(nil), cfg.Routes...)
	cp.Server.AllowedNetworks = append([]string(nil), cfg.Server.AllowedNetworks...)
	if cp.GoDaddy.APISecret != "" {
		cp.GoDaddy.APISecret = maskedSecret
	}
	return cp
}

func clientIP(r *http.Request) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(host)
}

// Config handlers

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, redactConfig(s.configMgr.Get()))
}

func (s *Server) handleUpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	// Pointer fields so clients may send a partial update.
	var req struct {
		HTTPPort        *int      `json:"http_port"`
		HTTPSPort       *int      `json:"https_port"`
		AdminPort       *int      `json:"admin_port"`
		AdminHost       *string   `json:"admin_host"`
		AllowedNetworks *[]string `json:"allowed_networks"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	next := s.configMgr.Get().Server
	before := next
	before.AllowedNetworks = append([]string(nil), next.AllowedNetworks...)

	for name, p := range map[string]*int{"http_port": req.HTTPPort, "https_port": req.HTTPSPort, "admin_port": req.AdminPort} {
		if p != nil && !validPort(*p) {
			jsonError(w, http.StatusBadRequest, name+" must be between 1 and 65535")
			return
		}
	}
	if req.HTTPPort != nil {
		next.HTTPPort = *req.HTTPPort
	}
	if req.HTTPSPort != nil {
		next.HTTPSPort = *req.HTTPSPort
	}
	if req.AdminPort != nil {
		next.AdminPort = *req.AdminPort
	}
	if next.HTTPPort == next.HTTPSPort || next.HTTPPort == next.AdminPort || next.HTTPSPort == next.AdminPort {
		jsonError(w, http.StatusBadRequest, "http_port, https_port and admin_port must all be different")
		return
	}
	if req.AdminHost != nil {
		h := strings.TrimSpace(*req.AdminHost)
		if h != "" {
			norm, err := normalizeTargetHost(h)
			if err != nil {
				jsonError(w, http.StatusBadRequest, "admin_host must be an IP address or hostname")
				return
			}
			h = norm
		}
		next.AdminHost = h
	}

	if req.AllowedNetworks != nil {
		networks := make([]string, 0, len(*req.AllowedNetworks))
		var parsed []*net.IPNet
		for _, raw := range *req.AllowedNetworks {
			n := strings.TrimSpace(raw)
			if n == "" {
				continue
			}
			ipNet, err := parseNetwork(n)
			if err != nil {
				jsonError(w, http.StatusBadRequest, err.Error())
				return
			}
			networks = append(networks, n)
			parsed = append(parsed, ipNet)
		}
		// An empty list falls back to loopback-only in NetworkWhitelist.
		if len(parsed) == 0 {
			_, v4, _ := net.ParseCIDR("127.0.0.0/8")
			_, v6, _ := net.ParseCIDR("::1/128")
			parsed = []*net.IPNet{v4, v6}
		}
		// Refuse a change that would lock the current operator out after restart.
		if ip := clientIP(r); ip != nil {
			allowed := false
			for _, n := range parsed {
				if n.Contains(ip) {
					allowed = true
					break
				}
			}
			if !allowed {
				jsonError(w, http.StatusBadRequest, fmt.Sprintf(
					"allowed_networks would block your current address %s; include it (e.g. %s) to avoid locking yourself out", ip, ip))
				return
			}
		}
		next.AllowedNetworks = networks
	}

	if err := s.configMgr.Update(func(cfg *config.Config) {
		cfg.Server = next
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	restart := before.HTTPPort != next.HTTPPort || before.HTTPSPort != next.HTTPSPort ||
		before.AdminPort != next.AdminPort || before.AdminHost != next.AdminHost ||
		strings.Join(before.AllowedNetworks, ",") != strings.Join(next.AllowedNetworks, ",")

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"status":           "updated",
		"restart_required": restart,
	})
}

func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	cfg := s.configMgr.Get()

	resp := map[string]interface{}{
		"config_encryption":      false,
		"csp_enforced":           true,
		"rate_limit":             map[string]int{"max_requests": RateLimitRequests, "window_seconds": int(RateLimitWindow / time.Second)},
		"allowed_networks_count": len(cfg.Server.AllowedNetworks),
		"godaddy_configured":     s.godaddyClient.IsConfigured(),
		"godaddy_base_url":       s.godaddyClient.BaseURL(),
		"acme_directory":         s.acmeClient.Directory(),
		"acme_staging":           strings.Contains(s.acmeClient.Directory(), "staging"),
	}
	secrets := s.configMgr.SecretsStatus()
	resp["secrets"] = secrets
	resp["config_encryption"] = secrets.Error == "" && (secrets.Mode == "env" || secrets.Mode == "file")
	if secrets.Error != "" {
		resp["encryption_error"] = secrets.Error
	}

	af, _ := s.authStore.Load()
	tokens := len(af.Tokens)
	resp["admin_login"] = map[string]interface{}{
		"password_set":           af.PasswordHash != "",
		"strong_password_policy": af.StrongPolicy,
		"require_secure_login":   s.security.RequireSecureLogin,
		"session_idle_timeout":   humanDuration(s.security.SessionIdle()),
		"session_max_age":        humanDuration(s.security.SessionMax()),
		"api_tokens":             tokens,
	}
	resp["admin_https"] = r.TLS != nil
	jsonResponse(w, http.StatusOK, resp)
}

// Route handlers

// routeInput is the writable subset of a route. Pointer fields distinguish
// "not sent" from zero values so PUT can merge instead of wiping fields
// (e.g. cert_file) the client did not include. ID and timestamps are
// accepted so a GET → edit → PUT round-trip works, but they are ignored.
type routeInput struct {
	ID         *string `json:"id"`
	Name       *string `json:"name"`
	Domain     *string `json:"domain"`
	PathPrefix *string `json:"path_prefix"`
	TargetHost *string `json:"target_host"`
	TargetPort *int    `json:"target_port"`
	TLSEnabled *bool   `json:"tls_enabled"`
	CertFile   *string `json:"cert_file"`
	KeyFile    *string `json:"key_file"`
	AutoCert   *bool   `json:"auto_cert"`
	Enabled    *bool   `json:"enabled"`
	CreatedAt  *string `json:"created_at"`
	UpdatedAt  *string `json:"updated_at"`
}

// apply validates in and merges it into r.
func (in routeInput) apply(r *config.ProxyRoute) error {
	if in.Name != nil {
		r.Name = strings.TrimSpace(*in.Name)
		if len(r.Name) > 120 {
			return badRequest("name is too long (max 120 characters)")
		}
	}
	if in.Domain != nil {
		d, err := normalizeDomain(*in.Domain)
		if err != nil {
			return badRequest("%s", err.Error())
		}
		r.Domain = d
	}
	if in.PathPrefix != nil {
		p, err := normalizePathPrefix(*in.PathPrefix)
		if err != nil {
			return badRequest("%s", err.Error())
		}
		r.PathPrefix = p
	}
	if in.TargetHost != nil {
		h, err := normalizeTargetHost(*in.TargetHost)
		if err != nil {
			return badRequest("%s", err.Error())
		}
		r.TargetHost = h
	}
	if in.TargetPort != nil {
		if !validPort(*in.TargetPort) {
			return badRequest("target_port must be between 1 and 65535")
		}
		r.TargetPort = *in.TargetPort
	}
	if in.CertFile != nil {
		r.CertFile = strings.TrimSpace(*in.CertFile)
	}
	if in.KeyFile != nil {
		r.KeyFile = strings.TrimSpace(*in.KeyFile)
	}
	if in.AutoCert != nil {
		r.AutoCert = *in.AutoCert
	}
	if in.Enabled != nil {
		r.Enabled = *in.Enabled
	}
	if in.TLSEnabled != nil {
		r.TLSEnabled = *in.TLSEnabled
	}
	// TLS without a certificate makes the proxy redirect HTTP to an HTTPS
	// listener that cannot complete a handshake, taking the site down.
	if r.TLSEnabled && (r.CertFile == "" || r.KeyFile == "") {
		return badRequest("TLS needs a certificate: request one on the Certificates page (TLS is switched on automatically once issued), or set cert_file and key_file")
	}
	return nil
}

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := s.configMgr.Get()
	jsonResponse(w, http.StatusOK, cfg.Routes)
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var in routeInput
	if err := decodeJSON(w, r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if in.Domain == nil || strings.TrimSpace(*in.Domain) == "" ||
		in.TargetHost == nil || strings.TrimSpace(*in.TargetHost) == "" ||
		in.TargetPort == nil || *in.TargetPort == 0 {
		jsonError(w, http.StatusBadRequest, "domain, target_host, and target_port are required")
		return
	}

	route := config.ProxyRoute{Enabled: true} // new routes are live unless told otherwise
	if in.ID != nil && *in.ID != "" {
		if !routeIDRe.MatchString(*in.ID) {
			jsonError(w, http.StatusBadRequest, "id may only contain letters, digits, '.', '_' and '-'")
			return
		}
		route.ID = *in.ID
	}
	if err := in.apply(&route); err != nil {
		writeUpdateError(w, err)
		return
	}

	created, err := s.configMgr.CreateRoute(route)
	if err != nil {
		writeUpdateError(w, err)
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_added", Payload: created})
	jsonResponse(w, http.StatusCreated, created)
}

func (s *Server) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	route := s.configMgr.GetRoute(id)
	if route == nil {
		jsonError(w, http.StatusNotFound, "route not found")
		return
	}
	jsonResponse(w, http.StatusOK, route)
}

func (s *Server) handleUpdateRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")

	var in routeInput
	if err := decodeJSON(w, r, &in); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	updated, err := s.configMgr.ModifyRoute(id, in.apply)
	if err != nil {
		writeUpdateError(w, err)
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_updated", Payload: updated})
	jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "updated", "route": updated})
}

func (s *Server) handleToggleRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	updated, err := s.configMgr.ModifyRoute(id, func(rt *config.ProxyRoute) error {
		rt.Enabled = !rt.Enabled
		return nil
	})
	if err != nil {
		writeUpdateError(w, err)
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_updated", Payload: updated})
	jsonResponse(w, http.StatusOK, map[string]interface{}{"status": "updated", "route": updated})
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.configMgr.RemoveRoute(id); err != nil {
		writeUpdateError(w, err)
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_deleted", Payload: map[string]string{"id": id}})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Health check handler — lightweight probe for load balancers / k8s liveness probes.
// Returns 200 OK with a JSON body. No auth required — the network whitelist middleware
// still applies; for k8s cluster-internal probes that should be fine.

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, http.StatusOK, map[string]string{
		"status": "ok",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// Status handler

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	statuses := s.engine.GetRouteStatus()
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"routes":    statuses,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// ACME handlers

func decodeDomainRequest(w http.ResponseWriter, r *http.Request, v interface{}, domain *string) bool {
	if err := decodeJSON(w, r, v); err != nil || strings.TrimSpace(*domain) == "" {
		jsonError(w, http.StatusBadRequest, "domain is required")
		return false
	}
	d, err := normalizeDomain(*domain)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return false
	}
	*domain = d
	return true
}

func (s *Server) handleACMERequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if !decodeDomainRequest(w, r, &req, &req.Domain) {
		return
	}

	// Register ACME account if needed
	ctx := r.Context()
	if err := s.acmeClient.Register(ctx); err != nil {
		jsonError(w, http.StatusInternalServerError, "ACME registration failed: "+err.Error())
		return
	}

	status, err := s.acmeClient.RequestCertificate(ctx, req.Domain)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "acme_challenge", Payload: status})
	jsonResponse(w, http.StatusOK, status)
}

func (s *Server) handleACMEComplete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain  string `json:"domain"`
		AutoDNS bool   `json:"auto_dns"`
	}
	if !decodeDomainRequest(w, r, &req, &req.Domain) {
		return
	}

	// Use a background context with a generous timeout so that WaitAuthorization
	// is not cut short by the HTTP server's 60-second WriteTimeout.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// If auto_dns is enabled and GoDaddy is configured, create the DNS record automatically
	if req.AutoDNS && s.godaddyClient.IsConfigured() {
		challenge := s.acmeClient.GetChallengeStatus(req.Domain)
		if challenge != nil && challenge.RecordVal != "" {
			err := s.godaddyClient.CreateTXTRecord(ctx, req.Domain, challenge.RecordName, challenge.RecordVal)
			if err != nil {
				jsonError(w, http.StatusInternalServerError, "auto DNS failed: "+err.Error())
				return
			}

			s.wsHub.Broadcast(WSMessage{Type: "dns_record_created", Payload: map[string]string{
				"domain": req.Domain,
				"record": challenge.RecordName,
			}})

			// Wait for DNS propagation (GoDaddy typically propagates within 30s)
			s.logger.Info("waiting for DNS propagation", "seconds", 30)
			time.Sleep(30 * time.Second)
		}
	}

	certPath, keyPath, err := s.acmeClient.CompleteChallengeAndFetchCert(ctx, req.Domain)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Attach the certificate to every route on this domain (each path-prefix
	// route is a separate entry), keeping all other route fields intact.
	for _, route := range s.configMgr.Get().Routes {
		if !strings.EqualFold(route.Domain, req.Domain) {
			continue
		}
		if _, err := s.configMgr.ModifyRoute(route.ID, func(rt *config.ProxyRoute) error {
			rt.TLSEnabled = true
			rt.CertFile = certPath
			rt.KeyFile = keyPath
			rt.AutoCert = true
			return nil
		}); err != nil {
			s.logger.Error("failed to update route with cert", "route", route.ID, "error", err)
		}
	}
	if err := s.engine.LoadCertificate(req.Domain, certPath, keyPath); err != nil {
		s.logger.Error("failed to load cert in proxy", "error", err)
	}

	s.wsHub.Broadcast(WSMessage{Type: "cert_obtained", Payload: map[string]string{
		"domain": req.Domain,
		"cert":   certPath,
	}})

	jsonResponse(w, http.StatusOK, map[string]string{
		"status":    "certificate obtained",
		"cert_file": certPath,
		"key_file":  keyPath,
	})
}

func (s *Server) handleACMEChallenges(w http.ResponseWriter, r *http.Request) {
	challenges := s.acmeClient.GetAllChallenges()
	jsonResponse(w, http.StatusOK, challenges)
}

func (s *Server) handleUpdateACMEConfig(w http.ResponseWriter, r *http.Request) {
	var acmeCfg config.ACMEConfig
	if err := decodeJSON(w, r, &acmeCfg); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	acmeCfg.Email = strings.TrimSpace(acmeCfg.Email)
	if acmeCfg.Email != "" && !validEmail(acmeCfg.Email) {
		jsonError(w, http.StatusBadRequest, "invalid ACME contact email")
		return
	}
	dir, err := normalizeACMEDirectory(acmeCfg.Directory, acmeCfg.UseStaging)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	acmeCfg.Directory = dir
	acmeCfg.UseStaging = strings.Contains(dir, "staging")
	acmeCfg.CertDir = strings.TrimSpace(acmeCfg.CertDir)

	if err := s.configMgr.Update(func(cfg *config.Config) {
		if acmeCfg.CertDir == "" {
			acmeCfg.CertDir = cfg.ACME.CertDir // never wipe the cert directory
		}
		cfg.ACME = acmeCfg
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.acmeClient.UpdateConfig(acmeCfg.Email, acmeCfg.Directory)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

// GoDaddy handlers

func (s *Server) handleUpdateGoDaddyConfig(w http.ResponseWriter, r *http.Request) {
	var gdCfg config.GoDaddyConfig
	if err := decodeJSON(w, r, &gdCfg); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	baseURL, err := normalizeGoDaddyBaseURL(gdCfg.BaseURL)
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	gdCfg.BaseURL = baseURL
	gdCfg.APIKey = strings.TrimSpace(gdCfg.APIKey)
	gdCfg.APISecret = strings.TrimSpace(gdCfg.APISecret)

	if err := s.configMgr.Update(func(cfg *config.Config) {
		// The UI only ever sees the masked secret; an empty or masked value
		// means "keep the stored one" rather than overwriting it.
		if gdCfg.APISecret == "" || gdCfg.APISecret == maskedSecret {
			gdCfg.APISecret = cfg.GoDaddy.APISecret
		}
		cfg.GoDaddy = gdCfg
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.godaddyClient.UpdateConfig(gdCfg.APIKey, gdCfg.APISecret, gdCfg.BaseURL)

	jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleVerifyGoDaddy(w http.ResponseWriter, r *http.Request) {
	if !s.godaddyClient.IsConfigured() {
		jsonError(w, http.StatusBadRequest, "GoDaddy API not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.godaddyClient.VerifyConnection(ctx); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "connected"})
}

func (s *Server) handleListGoDaddyDomains(w http.ResponseWriter, r *http.Request) {
	if !s.godaddyClient.IsConfigured() {
		jsonError(w, http.StatusBadRequest, "GoDaddy API not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	includeInactive := r.URL.Query().Get("include_inactive") == "true"
	domains, err := s.godaddyClient.ListDomainsSorted(ctx, includeInactive)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, domains)
}

// zoneFromPath validates the {domain} path value as a DNS zone name.
func zoneFromPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	d, err := normalizeDomain(r.PathValue("domain"))
	if err != nil || strings.HasPrefix(d, "*.") {
		jsonError(w, http.StatusBadRequest, "invalid domain name")
		return "", false
	}
	return d, true
}

func (s *Server) requireGoDaddy(w http.ResponseWriter) bool {
	if !s.godaddyClient.IsConfigured() {
		jsonError(w, http.StatusBadRequest, "GoDaddy API not configured")
		return false
	}
	return true
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	domain, ok := zoneFromPath(w, r)
	if !ok || !s.requireGoDaddy(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	records, err := s.godaddyClient.GetRecords(ctx, domain)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, records)
}

// validateRecord normalises and checks a DNS record before it reaches GoDaddy.
func validateRecord(rec *godaddy.DNSRecord) error {
	rec.Type = strings.ToUpper(strings.TrimSpace(rec.Type))
	rec.Name = strings.TrimSpace(rec.Name)
	rec.Data = strings.TrimSpace(rec.Data)
	if rec.Type == "" || rec.Name == "" || rec.Data == "" {
		return fmt.Errorf("type, name, and data are required")
	}
	if !validRecordType(rec.Type) {
		return fmt.Errorf("unsupported DNS record type %q", rec.Type)
	}
	if rec.Type == "SRV" {
		// SRV needs service, protocol, port and weight, which DNSRecord does not carry.
		return fmt.Errorf("SRV records are not supported here; create them in the GoDaddy dashboard")
	}
	if !validRecordName(rec.Name) {
		return fmt.Errorf("invalid DNS record name %q", rec.Name)
	}
	if rec.TTL == 0 {
		rec.TTL = 600
	}
	if rec.TTL < 600 || rec.TTL > 86400 {
		return fmt.Errorf("ttl must be between 600 and 86400 seconds")
	}
	switch rec.Type {
	case "A":
		if ip := net.ParseIP(rec.Data); ip == nil || ip.To4() == nil {
			return fmt.Errorf("A record value must be an IPv4 address")
		}
	case "AAAA":
		if ip := net.ParseIP(rec.Data); ip == nil || ip.To4() != nil {
			return fmt.Errorf("AAAA record value must be an IPv6 address")
		}
	case "CNAME":
		if _, err := normalizeDomain(rec.Data); err != nil {
			return fmt.Errorf("CNAME value must be a hostname")
		}
	}
	return nil
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain, ok := zoneFromPath(w, r)
	if !ok {
		return
	}

	var record godaddy.DNSRecord
	if err := decodeJSON(w, r, &record); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := validateRecord(&record); err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.requireGoDaddy(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.godaddyClient.CreateRecord(ctx, domain, record); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "dns_record_created", Payload: map[string]interface{}{
		"domain": domain,
		"record": record,
	}})

	jsonResponse(w, http.StatusCreated, map[string]string{"status": "created"})
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain, ok := zoneFromPath(w, r)
	if !ok {
		return
	}
	recordType := strings.ToUpper(r.PathValue("type"))
	name := r.PathValue("name")
	if !validRecordType(recordType) || !validRecordName(name) {
		jsonError(w, http.StatusBadRequest, "invalid record type or name")
		return
	}
	if !s.requireGoDaddy(w) {
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.godaddyClient.DeleteRecord(ctx, domain, recordType, name); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "dns_record_deleted", Payload: map[string]string{
		"domain": domain, "type": recordType, "name": name,
	}})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// handleAutoDNS creates an A record automatically via GoDaddy for a proxy route
func (s *Server) handleAutoDNS(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain    string `json:"domain"`
		Subdomain string `json:"subdomain"`
		IP        string `json:"ip"`
		Type      string `json:"type"` // "A" or "CNAME"
		Value     string `json:"value"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !s.godaddyClient.IsConfigured() {
		jsonError(w, http.StatusBadRequest, "GoDaddy API not configured")
		return
	}

	domain, err := normalizeDomain(req.Domain)
	if err != nil || !validRecordName(strings.TrimSpace(req.Subdomain)) {
		jsonError(w, http.StatusBadRequest, "valid domain and subdomain are required")
		return
	}
	req.Domain, req.Subdomain = domain, strings.TrimSpace(req.Subdomain)

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	switch strings.ToUpper(req.Type) {
	case "CNAME":
		target := strings.TrimSpace(req.Value)
		if _, err := normalizeDomain(target); err != nil {
			jsonError(w, http.StatusBadRequest, "CNAME value must be a hostname")
			return
		}
		err = s.godaddyClient.CreateCNAMERecord(ctx, req.Domain, req.Subdomain, target)
	default:
		ip := strings.TrimSpace(req.IP)
		if ip == "" {
			ip = strings.TrimSpace(req.Value)
		}
		if parsed := net.ParseIP(ip); parsed == nil || parsed.To4() == nil {
			jsonError(w, http.StatusBadRequest, "ip must be an IPv4 address")
			return
		}
		err = s.godaddyClient.CreateARecord(ctx, req.Domain, req.Subdomain, ip)
	}

	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "auto_dns_created", Payload: req})

	jsonResponse(w, http.StatusOK, map[string]string{"status": "DNS record created"})
}

// handleCertsStatus returns cert renewal metrics and per-domain expiry info.
func (s *Server) handleCertsStatus(w http.ResponseWriter, r *http.Request) {
	type certInfo struct {
		Domain        string `json:"domain"`
		CertFile      string `json:"cert_file"`
		ExpiresAt     string `json:"expires_at,omitempty"`
		DaysRemaining *int   `json:"days_remaining,omitempty"`
		NeedsRenewal  bool   `json:"needs_renewal"`
		AutoRenew     bool   `json:"auto_renew"`
		Error         string `json:"error,omitempty"`
	}

	var metrics struct {
		RenewalSuccess int64 `json:"renewal_success"`
		RenewalFailed  int64 `json:"renewal_failed"`
	}

	if s.certMgr != nil {
		m := s.certMgr.GetMetrics()
		metrics.RenewalSuccess = m.RenewalSuccess
		metrics.RenewalFailed = m.RenewalFailed
	}

	cfg := s.configMgr.Get()
	autoRenew := s.certMgr != nil && s.godaddyClient.IsConfigured()
	certs := []certInfo{}
	seen := map[string]bool{}
	for _, route := range cfg.Routes {
		if !route.TLSEnabled || route.CertFile == "" || seen[route.Domain] {
			continue
		}
		seen[route.Domain] = true // path-prefix routes share one certificate
		info := certInfo{
			Domain:   route.Domain,
			CertFile: route.CertFile,
			// The renewer publishes the DNS-01 TXT record through GoDaddy, so
			// renewal can only succeed while GoDaddy is configured.
			AutoRenew: autoRenew && route.Enabled,
		}
		if s.certMgr != nil {
			status, err := s.certMgr.GetCertStatus(route.Domain, route.CertFile)
			if err != nil {
				info.Error = err.Error()
			} else {
				days := status.DaysRemaining
				info.ExpiresAt = status.ExpiresAt.UTC().Format(time.RFC3339)
				info.DaysRemaining = &days
				info.NeedsRenewal = status.NeedsRenewal
			}
		}
		certs = append(certs, info)
	}

	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"metrics":   metrics,
		"certs":     certs,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

func (s *Server) Start(addr string) error {
	rateLimiter := NewRateLimiter(RateLimitRequests, RateLimitWindow)
	cfg := s.configMgr.Get()

	handler := Chain(
		http.Handler(s),
		SecurityHeaders,
		RequestLogger(s.logger),
		RateLimit(rateLimiter),
		NetworkWhitelist(cfg.Server.AllowedNetworks),
	)

	server := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      6 * time.Minute, // ACME completion can wait on DNS propagation + validation
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	if s.security.AdminTLS.Enabled {
		tlsCfg, fingerprint, err := s.adminTLSConfig()
		if err != nil {
			return err
		}
		server.TLSConfig = tlsCfg
		s.logger.Info("starting admin API over HTTPS", "addr", addr, "cert_sha256", fingerprint)
		return server.ListenAndServeTLS("", "")
	}

	s.logger.Info("starting admin API", "addr", addr)
	return server.ListenAndServe()
}

func (s *Server) Handler() http.Handler {
	return s
}

// humanDuration prints whole days or hours compactly ("7d", "12h"), falling
// back to Go's format for anything finer.
func humanDuration(d time.Duration) string {
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	default:
		return d.String()
	}
}
