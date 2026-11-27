// Package config manages ProxyGate configuration with file-based persistence and hot reload.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

)

type ProxyRoute struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Domain      string `json:"domain"`
	// PathPrefix, when non-empty, only matches requests whose URL path starts
	// with this value.  More-specific (longer) prefixes win over shorter ones.
	// An empty PathPrefix matches all paths for the domain (catch-all).
	PathPrefix  string `json:"path_prefix,omitempty"`
	TargetHost  string `json:"target_host"`
	TargetPort  int    `json:"target_port"`
	TLSEnabled  bool   `json:"tls_enabled"`
	CertFile    string `json:"cert_file,omitempty"`
	KeyFile     string `json:"key_file,omitempty"`
	AutoCert    bool   `json:"auto_cert"`
	Enabled     bool   `json:"enabled"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

type GoDaddyConfig struct {
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
	BaseURL   string `json:"base_url"`
}

type ACMEConfig struct {
	Email      string `json:"email"`
	Directory  string `json:"directory"`
	CertDir    string `json:"cert_dir"`
	UseStaging bool   `json:"use_staging"`
}

type ServerConfig struct {
	HTTPPort        int      `json:"http_port"`
	HTTPSPort       int      `json:"https_port"`
	AdminPort       int      `json:"admin_port"`
	AdminHost       string   `json:"admin_host"`
	AllowedNetworks []string `json:"allowed_networks"`
}

type Config struct {
	Server   ServerConfig   `json:"server"`
	Routes   []ProxyRoute   `json:"routes"`
	GoDaddy  GoDaddyConfig  `json:"godaddy"`
	ACME     ACMEConfig     `json:"acme"`
	Security SecurityConfig `json:"security"`
}

type Manager struct {
	mu        sync.RWMutex
	config    *Config
	filePath  string
	listeners []func(*Config)

	// keyMode records where the encryption key came from ("env" or "file").
	keyMode string
	// stash keeps ciphertext of fields that could not be decrypted, so a
	// save does not destroy them; secretsErr explains why.
	stash      map[string]string
	secretsErr error
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			HTTPPort:  8080,
			HTTPSPort: 8443,
			AdminPort:       9090,
			AdminHost:       "127.0.0.1",
			AllowedNetworks: []string{"127.0.0.0/8", "::1/128"},
		},
		Routes: []ProxyRoute{},
		GoDaddy: GoDaddyConfig{
			BaseURL: "https://api.godaddy.com",
		},
		ACME: ACMEConfig{
			// Staging until the operator opts into production certificates.
			Directory:  "https://acme-staging-v02.api.letsencrypt.org/directory",
			CertDir:    "./certs",
			UseStaging: true,
		},
	}
}

func NewManager(filePath string) (*Manager, error) {
	m := &Manager{
		filePath: filePath,
	}

	if err := m.load(); err != nil {
		if os.IsNotExist(err) {
			m.config = DefaultConfig()
			if err := m.save(); err != nil {
				return nil, fmt.Errorf("creating default config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("loading config: %w", err)
		}
	}

	return m, nil
}

func (m *Manager) load() error {
	data, err := os.ReadFile(m.filePath)
	if err != nil {
		return err
	}

	cfg := DefaultConfig()
	if err := json.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("parsing config: %w", err)
	}

	// In memory, sensitive fields are always plaintext. Encrypted fields are
	// decrypted here; plaintext ones are encrypted on disk by the save below.
	m.decryptLoaded(cfg)
	migrate := m.secretsErr == nil && cfg.Security.EncryptSecretsEnabled() && hasSensitivePlaintextFields(cfg)

	m.config = cfg
	if migrate {
		// Non-fatal: if the write fails the next successful save encrypts.
		_ = m.save()
	}
	return nil
}

func (m *Manager) save() error {
	// Build the version to write to disk.
	// If a key is available, encrypt sensitive fields before persisting.
	diskCfg := *m.config
	diskCfg.Routes = make([]ProxyRoute, len(m.config.Routes))
	copy(diskCfg.Routes, m.config.Routes)

	if err := m.encryptForDisk(&diskCfg); err != nil {
		return err
	}

	return m.writeConfig(&diskCfg)
}

// writeConfig serialises cfg atomically to m.filePath via a tmp-rename.
func (m *Manager) writeConfig(cfg *Config) error {
	dir := filepath.Dir(m.filePath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}

	tmpFile := m.filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0640); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}

	if err := os.Rename(tmpFile, m.filePath); err != nil {
		os.Remove(tmpFile)
		return fmt.Errorf("renaming config: %w", err)
	}

	return nil
}

func (m *Manager) Get() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cp := *m.config
	cp.Routes = make([]ProxyRoute, len(m.config.Routes))
	copy(cp.Routes, m.config.Routes)
	return &cp
}

func (m *Manager) Update(fn func(*Config)) error {
	return m.update(func(cfg *Config) error {
		fn(cfg)
		return nil
	})
}

// update runs fn under the write lock. If fn returns an error nothing is
// saved or broadcast; fn must not mutate cfg before deciding to fail.
func (m *Manager) update(fn func(*Config) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := fn(m.config); err != nil {
		return err
	}

	if err := m.save(); err != nil {
		return err
	}

	cfg := *m.config
	for _, listener := range m.listeners {
		listener(&cfg)
	}

	return nil
}

func (m *Manager) OnChange(fn func(*Config)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listeners = append(m.listeners, fn)
}

func (m *Manager) AddRoute(route ProxyRoute) error {
	return m.Update(func(cfg *Config) {
		now := time.Now().UTC().Format(time.RFC3339)
		route.CreatedAt = now
		route.UpdatedAt = now
		if route.ID == "" {
			route.ID = fmt.Sprintf("route_%d", time.Now().UnixNano())
		}
		cfg.Routes = append(cfg.Routes, route)
	})
}

func (m *Manager) UpdateRoute(id string, updated ProxyRoute) error {
	return m.Update(func(cfg *Config) {
		for i, r := range cfg.Routes {
			if r.ID == id {
				updated.ID = id
				updated.CreatedAt = r.CreatedAt
				updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
				cfg.Routes[i] = updated
				return
			}
		}
	})
}

func (m *Manager) DeleteRoute(id string) error {
	return m.Update(func(cfg *Config) {
		for i, r := range cfg.Routes {
			if r.ID == id {
				cfg.Routes = append(cfg.Routes[:i], cfg.Routes[i+1:]...)
				return
			}
		}
	})
}

var (
	// ErrRouteNotFound is returned when no route has the requested ID.
	ErrRouteNotFound = errors.New("route not found")
	// ErrRouteConflict is returned when another route already serves the
	// same domain + path prefix combination.
	ErrRouteConflict = errors.New("a route with the same domain and path prefix already exists")
)

// routeKey normalises the (domain, path prefix) pair used for collision checks.
func routeKey(r ProxyRoute) string {
	return strings.ToLower(strings.TrimSpace(r.Domain)) + "\x00" + strings.TrimSpace(r.PathPrefix)
}

func hasCollision(routes []ProxyRoute, candidate ProxyRoute, excludeID string) bool {
	key := routeKey(candidate)
	for _, r := range routes {
		if r.ID != excludeID && routeKey(r) == key {
			return true
		}
	}
	return false
}

// CreateRoute adds a route, assigning ID and timestamps, and returns the
// stored copy. It fails with ErrRouteConflict if the domain + path prefix
// is already taken.
func (m *Manager) CreateRoute(route ProxyRoute) (ProxyRoute, error) {
	err := m.update(func(cfg *Config) error {
		if hasCollision(cfg.Routes, route, "") {
			return ErrRouteConflict
		}
		now := time.Now().UTC().Format(time.RFC3339)
		route.CreatedAt = now
		route.UpdatedAt = now
		if route.ID == "" {
			route.ID = fmt.Sprintf("route_%d", time.Now().UnixNano())
		}
		for _, r := range cfg.Routes {
			if r.ID == route.ID {
				return fmt.Errorf("route id %q already exists", route.ID)
			}
		}
		cfg.Routes = append(cfg.Routes, route)
		return nil
	})
	if err != nil {
		return ProxyRoute{}, err
	}
	return route, nil
}

// ModifyRoute applies fn to a copy of the route with the given ID and stores
// the result atomically. ID and CreatedAt are preserved; UpdatedAt is
// refreshed. If fn returns an error the route is left unchanged.
func (m *Manager) ModifyRoute(id string, fn func(*ProxyRoute) error) (ProxyRoute, error) {
	var result ProxyRoute
	err := m.update(func(cfg *Config) error {
		for i, r := range cfg.Routes {
			if r.ID != id {
				continue
			}
			updated := r
			if err := fn(&updated); err != nil {
				return err
			}
			updated.ID = r.ID
			updated.CreatedAt = r.CreatedAt
			updated.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			if hasCollision(cfg.Routes, updated, id) {
				return ErrRouteConflict
			}
			cfg.Routes[i] = updated
			result = updated
			return nil
		}
		return ErrRouteNotFound
	})
	return result, err
}

// RemoveRoute deletes the route with the given ID, returning
// ErrRouteNotFound if it does not exist.
func (m *Manager) RemoveRoute(id string) error {
	return m.update(func(cfg *Config) error {
		for i, r := range cfg.Routes {
			if r.ID == id {
				cfg.Routes = append(cfg.Routes[:i], cfg.Routes[i+1:]...)
				return nil
			}
		}
		return ErrRouteNotFound
	})
}

func (m *Manager) GetRoute(id string) *ProxyRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, r := range m.config.Routes {
		if r.ID == id {
			cp := r
			return &cp
		}
	}
	return nil
}

func (m *Manager) Reload() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := m.load(); err != nil {
		return err
	}

	cfg := *m.config
	for _, listener := range m.listeners {
		listener(&cfg)
	}

	return nil
}

// Dir returns the directory holding the config file; ProxyGate keeps its
// other state (auth file, setup code, generated keys) next to it.
func (m *Manager) Dir() string {
	return filepath.Dir(m.filePath)
}
