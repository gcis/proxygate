package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gcis/proxygate/internal/auth"
)

const (
	sessionCookie = "proxygate_session"

	loginMaxFailures = 5
	loginWindow      = 15 * time.Minute
	// Each argon2id check uses ~46 MiB; cap concurrent checks so a burst of
	// login attempts cannot exhaust memory on small devices.
	maxConcurrentHashes = 2
)

// publicAPI lists the /api paths reachable without a session or token.
var publicAPI = map[string]bool{
	"/api/auth/status": true,
	"/api/auth/login":  true,
	"/api/auth/setup":  true,
	"/api/auth/logout": true,
}

// requiresAuth reports whether path needs an authenticated caller. The UI's
// static files, /docs/ and /healthz stay public so the login page can load.
func requiresAuth(path string) bool {
	if path == "/ws" {
		return true
	}
	return strings.HasPrefix(path, "/api/") && !publicAPI[path]
}

// authenticated checks a Bearer API token first, then the session cookie.
func (s *Server) authenticated(r *http.Request) bool {
	if h := r.Header.Get("Authorization"); h != "" {
		scheme, token, ok := strings.Cut(h, " ")
		return ok && strings.EqualFold(scheme, "Bearer") && s.authStore.CheckToken(strings.TrimSpace(token))
	}
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	f, err := s.authStore.Load()
	if err != nil || f.PasswordHash == "" {
		return false
	}
	return s.sessions.Valid(c.Value, f.SessionEpoch)
}

// transport describes how the caller reached the admin listener.
type transport struct {
	secure bool // HTTPS
	local  bool // loopback client
}

func transportOf(r *http.Request) transport {
	ip := clientIP(r)
	return transport{secure: r.TLS != nil, local: ip != nil && ip.IsLoopback()}
}

// passwordOverNetworkUnencrypted is true when a password would cross the
// network in plain HTTP.
func (t transport) passwordOverNetworkUnencrypted() bool { return !t.secure && !t.local }

func (s *Server) refuseInsecureLogin(w http.ResponseWriter, r *http.Request) bool {
	if s.security.RequireSecureLogin && transportOf(r).passwordOverNetworkUnencrypted() {
		jsonError(w, http.StatusForbidden,
			"login over plain HTTP is disabled (security.require_secure_login); use HTTPS or connect from localhost")
		return true
	}
	return false
}

// throttled answers 429 when the caller has too many recent failures.
func (s *Server) throttled(w http.ResponseWriter, r *http.Request) bool {
	if blocked, wait := s.loginLimiter.Blocked(clientKey(r)); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		jsonError(w, http.StatusTooManyRequests,
			fmt.Sprintf("too many failed attempts; try again in %d minutes", int(wait.Minutes())+1))
		return true
	}
	return false
}

func clientKey(r *http.Request) string {
	if ip := clientIP(r); ip != nil {
		return ip.String()
	}
	return r.RemoteAddr
}

// withHashSlot runs fn while holding one of the limited password-hash slots.
func (s *Server) withHashSlot(fn func()) {
	s.hashSlots <- struct{}{}
	defer func() { <-s.hashSlots }()
	fn()
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request) error {
	f, err := s.authStore.Load()
	if err != nil {
		return err
	}
	// A fresh ID at every login prevents session fixation.
	if old, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(old.Value)
	}
	id, err := s.sessions.Create(f.SessionEpoch)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(s.security.SessionMax().Seconds()),
	})
	return nil
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/", MaxAge: -1,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	f, err := s.authStore.Load()
	if err != nil {
		jsonError(w, http.StatusInternalServerError, "reading admin credentials: "+err.Error())
		return
	}
	t := transportOf(r)
	resp := map[string]interface{}{
		"setup_required":         f.PasswordHash == "",
		"authenticated":          s.authenticated(r),
		"strong_password_policy": f.StrongPolicy,
		"https":                  t.secure,
		"insecure_transport":     t.passwordOverNetworkUnencrypted(),
		"require_secure_login":   s.security.RequireSecureLogin,
	}
	if f.PasswordHash == "" {
		resp["setup_code_path"] = s.authStore.SetupCodePath()
	}
	jsonResponse(w, http.StatusOK, resp)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		SetupCode    string `json:"setup_code"`
		Password     string `json:"password"`
		StrongPolicy bool   `json:"strong_password_policy"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.refuseInsecureLogin(w, r) || s.throttled(w, r) {
		return
	}

	var err error
	s.withHashSlot(func() { err = s.authStore.CompleteSetup(req.SetupCode, req.Password, req.StrongPolicy) })
	switch {
	case errors.Is(err, auth.ErrBadSetupCode):
		s.loginLimiter.Fail(clientKey(r))
		jsonError(w, http.StatusUnauthorized, "the setup code is not correct; it is in "+s.authStore.SetupCodePath())
		return
	case errors.Is(err, auth.ErrSetupDone):
		jsonError(w, http.StatusConflict, "an admin password is already set; sign in instead")
		return
	case err != nil:
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.loginLimiter.Succeed(clientKey(r))
	s.logger.Info("admin password set during first setup", "remote", r.RemoteAddr, "strong_policy", req.StrongPolicy)
	if err := s.startSession(w, r); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.refuseInsecureLogin(w, r) || s.throttled(w, r) {
		return
	}
	if required, _ := s.authStore.SetupRequired(); required {
		jsonError(w, http.StatusConflict, "no admin password is set yet; complete setup first")
		return
	}

	var ok bool
	s.withHashSlot(func() { ok = s.authStore.CheckPassword(req.Password) })
	if !ok {
		s.loginLimiter.Fail(clientKey(r))
		s.logger.Warn("admin login failed", "remote", r.RemoteAddr)
		jsonError(w, http.StatusUnauthorized, "incorrect password")
		return
	}
	s.loginLimiter.Succeed(clientKey(r))
	if err := s.startSession(w, r); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("admin login", "remote", r.RemoteAddr)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.Delete(c.Value)
	}
	clearSessionCookie(w, r)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "signed out"})
}

func (s *Server) handleAuthChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if s.refuseInsecureLogin(w, r) || s.throttled(w, r) {
		return
	}

	var ok bool
	s.withHashSlot(func() { ok = s.authStore.CheckPassword(req.CurrentPassword) })
	if !ok {
		s.loginLimiter.Fail(clientKey(r))
		jsonError(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}
	var err error
	s.withHashSlot(func() { err = s.authStore.SetPassword(req.NewPassword, nil) })
	if err != nil {
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	}
	// The epoch changed, so every other session is now invalid; keep this one.
	if err := s.startSession(w, r); err != nil {
		jsonError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.logger.Info("admin password changed; other sessions signed out", "remote", r.RemoteAddr)
	jsonResponse(w, http.StatusOK, map[string]string{"status": "password changed"})
}
