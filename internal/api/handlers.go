package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gcis/proxygate/internal/acme"
	"github.com/gcis/proxygate/internal/config"
	"github.com/gcis/proxygate/internal/godaddy"
	"github.com/gcis/proxygate/internal/proxy"
)

type Server struct {
	configMgr *config.Manager
	engine    *proxy.Engine
	acmeClient *acme.Client
	godaddyClient *godaddy.Client
	wsHub     *WSHub
	logger    *slog.Logger
	mux       *http.ServeMux
}

func NewServer(
	cfgMgr *config.Manager,
	engine *proxy.Engine,
	acmeClient *acme.Client,
	godaddyClient *godaddy.Client,
	logger *slog.Logger,
) *Server {
	s := &Server{
		configMgr:     cfgMgr,
		engine:        engine,
		acmeClient:    acmeClient,
		godaddyClient: godaddyClient,
		wsHub:         NewWSHub(logger),
		logger:        logger,
		mux:           http.NewServeMux(),
	}

	s.registerRoutes()

	// Notify UI on config changes
	cfgMgr.OnChange(func(cfg *config.Config) {
		s.wsHub.Broadcast(WSMessage{Type: "config_changed", Payload: cfg})
	})

	return s
}

func (s *Server) registerRoutes() {
	// API routes
	s.mux.HandleFunc("GET /api/config", s.handleGetConfig)
	s.mux.HandleFunc("PUT /api/config/server", s.handleUpdateServerConfig)

	// Routes CRUD
	s.mux.HandleFunc("GET /api/routes", s.handleListRoutes)
	s.mux.HandleFunc("POST /api/routes", s.handleCreateRoute)
	s.mux.HandleFunc("GET /api/routes/{id}", s.handleGetRoute)
	s.mux.HandleFunc("PUT /api/routes/{id}", s.handleUpdateRoute)
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

	// Health check (for load balancers and k8s probes)
	s.mux.HandleFunc("GET /healthz", s.handleHealthz)

	// WebSocket
	s.mux.HandleFunc("GET /ws", s.wsHub.HandleWS)

	// Static UI files
	s.mux.HandleFunc("GET /", s.handleUI)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// CORS for local dev
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	s.mux.ServeHTTP(w, r)
}

func jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	jsonResponse(w, status, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

// Config handlers

func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.configMgr.Get()
	// Redact sensitive fields
	if cfg.GoDaddy.APISecret != "" {
		cfg.GoDaddy.APISecret = "********"
	}
	jsonResponse(w, http.StatusOK, cfg)
}

func (s *Server) handleUpdateServerConfig(w http.ResponseWriter, r *http.Request) {
	var serverCfg config.ServerConfig
	if err := decodeJSON(r, &serverCfg); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.configMgr.Update(func(cfg *config.Config) {
		cfg.Server = serverCfg
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

// Route handlers

func (s *Server) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	cfg := s.configMgr.Get()
	jsonResponse(w, http.StatusOK, cfg.Routes)
}

func (s *Server) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	var route config.ProxyRoute
	if err := decodeJSON(r, &route); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if route.Domain == "" || route.TargetHost == "" || route.TargetPort == 0 {
		jsonError(w, http.StatusBadRequest, "domain, target_host, and target_port are required")
		return
	}

	// Validate domain format
	if strings.ContainsAny(route.Domain, " /\\") {
		jsonError(w, http.StatusBadRequest, "invalid domain format")
		return
	}

	if err := s.configMgr.AddRoute(route); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_added", Payload: route})
	jsonResponse(w, http.StatusCreated, route)
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

	var route config.ProxyRoute
	if err := decodeJSON(r, &route); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.configMgr.UpdateRoute(id, route); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.wsHub.Broadcast(WSMessage{Type: "route_updated", Payload: route})
	jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.configMgr.DeleteRoute(id); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
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

func (s *Server) handleACMERequest(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Domain == "" {
		jsonError(w, http.StatusBadRequest, "domain is required")
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
	if err := decodeJSON(r, &req); err != nil || req.Domain == "" {
		jsonError(w, http.StatusBadRequest, "domain is required")
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

	// Update route with certificate
	cfg := s.configMgr.Get()
	for _, route := range cfg.Routes {
		if route.Domain == req.Domain {
			if err := s.configMgr.UpdateRoute(route.ID, config.ProxyRoute{
				Name:       route.Name,
				Domain:     route.Domain,
				TargetHost: route.TargetHost,
				TargetPort: route.TargetPort,
				TLSEnabled: true,
				CertFile:   certPath,
				KeyFile:    keyPath,
				AutoCert:   true,
				Enabled:    route.Enabled,
			}); err != nil {
				s.logger.Error("failed to update route with cert", "error", err)
			}

			// Reload certificate in proxy
			if err := s.engine.LoadCertificate(req.Domain, certPath, keyPath); err != nil {
				s.logger.Error("failed to load cert in proxy", "error", err)
			}
			break
		}
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
	if err := decodeJSON(r, &acmeCfg); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := s.configMgr.Update(func(cfg *config.Config) {
		cfg.ACME = acmeCfg
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

// GoDaddy handlers

func (s *Server) handleUpdateGoDaddyConfig(w http.ResponseWriter, r *http.Request) {
	var gdCfg config.GoDaddyConfig
	if err := decodeJSON(r, &gdCfg); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	s.godaddyClient.UpdateCredentials(gdCfg.APIKey, gdCfg.APISecret)

	if err := s.configMgr.Update(func(cfg *config.Config) {
		cfg.GoDaddy = gdCfg
	}); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

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

	domains, err := s.godaddyClient.ListDomains(ctx)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, domains)
}

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	records, err := s.godaddyClient.GetRecords(ctx, domain)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

	jsonResponse(w, http.StatusOK, records)
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	domain := r.PathValue("domain")

	var record godaddy.DNSRecord
	if err := decodeJSON(r, &record); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
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
	domain := r.PathValue("domain")
	recordType := r.PathValue("type")
	name := r.PathValue("name")

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	if err := s.godaddyClient.DeleteRecord(ctx, domain, recordType, name); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}

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
	if err := decodeJSON(r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if !s.godaddyClient.IsConfigured() {
		jsonError(w, http.StatusBadRequest, "GoDaddy API not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	var err error
	switch req.Type {
	case "CNAME":
		err = s.godaddyClient.CreateCNAMERecord(ctx, req.Domain, req.Subdomain, req.Value)
	default:
		ip := req.IP
		if ip == "" {
			ip = req.Value
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

func (s *Server) Start(addr string) error {
	rateLimiter := NewRateLimiter(1000, time.Minute)
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
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	s.logger.Info("starting admin API", "addr", addr)
	return server.ListenAndServe()
}

func (s *Server) Handler() http.Handler {
	return s
}
