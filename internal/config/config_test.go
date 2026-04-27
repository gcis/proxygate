package config_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/gcis/proxygate/internal/config"
)

// ─── DefaultConfig ────────────────────────────────────────────────────────────

func TestDefaultConfig(t *testing.T) {
	cfg := config.DefaultConfig()

	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("HTTPPort: want 8080, got %d", cfg.Server.HTTPPort)
	}
	if cfg.Server.HTTPSPort != 8443 {
		t.Errorf("HTTPSPort: want 8443, got %d", cfg.Server.HTTPSPort)
	}
	if cfg.Server.AdminPort != 9090 {
		t.Errorf("AdminPort: want 9090, got %d", cfg.Server.AdminPort)
	}
	if cfg.Server.AdminHost != "127.0.0.1" {
		t.Errorf("AdminHost: want 127.0.0.1, got %s", cfg.Server.AdminHost)
	}
	if len(cfg.Server.AllowedNetworks) == 0 {
		t.Error("AllowedNetworks: want non-empty slice, got empty")
	}
	if len(cfg.Routes) != 0 {
		t.Errorf("Routes: want empty, got %d routes", len(cfg.Routes))
	}
	if cfg.ACME.UseStaging != true {
		t.Error("ACME.UseStaging: want true by default")
	}
}

// ─── NewManager ───────────────────────────────────────────────────────────────

func TestNewManager_CreatesDefaultWhenFileMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("config file was not created on disk")
	}

	cfg := mgr.Get()
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("default HTTPPort: want 8080, got %d", cfg.Server.HTTPPort)
	}
}

func TestNewManager_LoadsExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	// Write a custom config to disk first.
	existing := config.DefaultConfig()
	existing.Server.HTTPPort = 8080
	existing.Routes = []config.ProxyRoute{
		{ID: "r1", Name: "app", Domain: "app.example.com", TargetHost: "localhost", TargetPort: 3000, Enabled: true},
	}
	data, _ := json.MarshalIndent(existing, "", "  ")
	if err := os.WriteFile(path, data, 0640); err != nil {
		t.Fatalf("setup: %v", err)
	}

	mgr, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}

	cfg := mgr.Get()
	if cfg.Server.HTTPPort != 8080 {
		t.Errorf("HTTPPort: want 8080, got %d", cfg.Server.HTTPPort)
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Domain != "app.example.com" {
		t.Errorf("Routes: unexpected value %+v", cfg.Routes)
	}
}

func TestNewManager_ReturnsErrorForInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	os.WriteFile(path, []byte("{invalid json"), 0640) //nolint:errcheck

	_, err := config.NewManager(path)
	if err == nil {
		t.Error("expected error for invalid JSON, got nil")
	}
}

// ─── Get ──────────────────────────────────────────────────────────────────────

func TestGet_ReturnsCopy(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))

	cfg := mgr.Get()
	cfg.Server.HTTPPort = 9999 // mutate the returned copy

	// Manager should still have the original value.
	if mgr.Get().Server.HTTPPort == 9999 {
		t.Error("Get() did not return a deep copy — mutation leaked into manager state")
	}
}

func TestGet_RoutesAreCopied(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Name: "test", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	routes := mgr.Get().Routes
	routes[0].Domain = "mutated.com"

	if mgr.Get().Routes[0].Domain == "mutated.com" {
		t.Error("Get() routes slice is shared — mutation leaked into manager state")
	}
}

// ─── AddRoute ─────────────────────────────────────────────────────────────────

func TestAddRoute_AutoAssignsID(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if err := mgr.AddRoute(config.ProxyRoute{Name: "test", Domain: "example.com", TargetHost: "localhost", TargetPort: 3000}); err != nil {
		t.Fatalf("AddRoute: %v", err)
	}
	r := mgr.Get().Routes[0]
	if r.ID == "" {
		t.Error("expected auto-assigned ID, got empty string")
	}
	if r.CreatedAt == "" {
		t.Error("expected CreatedAt to be set")
	}
	if r.UpdatedAt == "" {
		t.Error("expected UpdatedAt to be set")
	}
}

func TestAddRoute_PreservesExplicitID(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "custom-id", Name: "test", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck
	if got := mgr.Get().Routes[0].ID; got != "custom-id" {
		t.Errorf("ID: want custom-id, got %s", got)
	}
}

func TestAddRoute_FiresListeners(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))

	var called int
	mgr.OnChange(func(_ *config.Config) { called++ })
	mgr.OnChange(func(_ *config.Config) { called++ })

	mgr.AddRoute(config.ProxyRoute{Name: "test", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	if called != 2 {
		t.Errorf("expected 2 listener calls, got %d", called)
	}
}

// ─── UpdateRoute ──────────────────────────────────────────────────────────────

func TestUpdateRoute_UpdatesFields(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Name: "original", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	updated := config.ProxyRoute{Name: "updated", Domain: "b.com", TargetHost: "127.0.0.1", TargetPort: 4000}
	if err := mgr.UpdateRoute("r1", updated); err != nil {
		t.Fatalf("UpdateRoute: %v", err)
	}

	r := mgr.Get().Routes[0]
	if r.Name != "updated" {
		t.Errorf("Name: want updated, got %s", r.Name)
	}
	if r.ID != "r1" {
		t.Errorf("ID must be preserved: want r1, got %s", r.ID)
	}
	if r.UpdatedAt == "" {
		t.Error("UpdatedAt should be set after update")
	}
}

func TestUpdateRoute_PreservesCreatedAt(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Name: "original", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	original := mgr.Get().Routes[0].CreatedAt

	mgr.UpdateRoute("r1", config.ProxyRoute{Name: "updated", Domain: "b.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	if got := mgr.Get().Routes[0].CreatedAt; got != original {
		t.Errorf("CreatedAt changed after update: was %s, now %s", original, got)
	}
}

// ─── DeleteRoute ──────────────────────────────────────────────────────────────

func TestDeleteRoute_RemovesCorrectRoute(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Name: "first", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000})  //nolint:errcheck
	mgr.AddRoute(config.ProxyRoute{ID: "r2", Name: "second", Domain: "b.com", TargetHost: "localhost", TargetPort: 3001}) //nolint:errcheck
	mgr.AddRoute(config.ProxyRoute{ID: "r3", Name: "third", Domain: "c.com", TargetHost: "localhost", TargetPort: 3002})  //nolint:errcheck

	if err := mgr.DeleteRoute("r2"); err != nil {
		t.Fatalf("DeleteRoute: %v", err)
	}

	routes := mgr.Get().Routes
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes after delete, got %d", len(routes))
	}
	for _, r := range routes {
		if r.ID == "r2" {
			t.Error("deleted route r2 still present")
		}
	}
}

func TestDeleteRoute_NonexistentIDIsNoOp(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Name: "test", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	if err := mgr.DeleteRoute("does-not-exist"); err != nil {
		t.Fatalf("DeleteRoute nonexistent: %v", err)
	}
	if len(mgr.Get().Routes) != 1 {
		t.Errorf("expected 1 route to remain, got %d", len(mgr.Get().Routes))
	}
}

// ─── GetRoute ─────────────────────────────────────────────────────────────────

func TestGetRoute_ReturnsCorrectRoute(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	mgr.AddRoute(config.ProxyRoute{ID: "r1", Domain: "a.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck
	mgr.AddRoute(config.ProxyRoute{ID: "r2", Domain: "b.com", TargetHost: "localhost", TargetPort: 3001}) //nolint:errcheck

	r := mgr.GetRoute("r2")
	if r == nil {
		t.Fatal("expected route, got nil")
	}
	if r.Domain != "b.com" {
		t.Errorf("Domain: want b.com, got %s", r.Domain)
	}
}

func TestGetRoute_ReturnsNilForMissingID(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))
	if r := mgr.GetRoute("nonexistent"); r != nil {
		t.Errorf("expected nil for missing route, got %+v", r)
	}
}

// ─── Persistence ──────────────────────────────────────────────────────────────

func TestPersistence_RouteSurvivestNewManager(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	mgr1, _ := config.NewManager(path)
	mgr1.AddRoute(config.ProxyRoute{ID: "r1", Name: "persistent", Domain: "example.com", TargetHost: "localhost", TargetPort: 3000}) //nolint:errcheck

	mgr2, err := config.NewManager(path)
	if err != nil {
		t.Fatalf("second NewManager: %v", err)
	}

	routes := mgr2.Get().Routes
	if len(routes) != 1 {
		t.Fatalf("expected 1 route after reload, got %d", len(routes))
	}
	if routes[0].Name != "persistent" {
		t.Errorf("Name: want persistent, got %s", routes[0].Name)
	}
}

// ─── Reload ───────────────────────────────────────────────────────────────────

func TestReload_ReadsUpdatedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")

	mgr, _ := config.NewManager(path)
	if len(mgr.Get().Routes) != 0 {
		t.Fatal("expected empty routes initially")
	}

	// Write new config directly to disk (simulating external change).
	updated := config.DefaultConfig()
	updated.Routes = []config.ProxyRoute{
		{ID: "r1", Name: "hot", Domain: "hot.example.com", TargetHost: "localhost", TargetPort: 5000, Enabled: true},
	}
	data, _ := json.MarshalIndent(updated, "", "  ")
	os.WriteFile(path, data, 0640) //nolint:errcheck

	if err := mgr.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if len(mgr.Get().Routes) != 1 {
		t.Errorf("expected 1 route after reload, got %d", len(mgr.Get().Routes))
	}
}

func TestReload_FiresListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	mgr, _ := config.NewManager(path)

	fired := false
	mgr.OnChange(func(_ *config.Config) { fired = true })

	mgr.Reload() //nolint:errcheck

	if !fired {
		t.Error("OnChange listener not fired after Reload")
	}
}

// ─── Concurrency ──────────────────────────────────────────────────────────────

func TestConcurrentAccess_NoRace(t *testing.T) {
	mgr, _ := config.NewManager(filepath.Join(t.TempDir(), "config.json"))

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mgr.Get()
		}()
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mgr.AddRoute(config.ProxyRoute{ //nolint:errcheck
				Name: "concurrent", Domain: "concurrent.com", TargetHost: "localhost", TargetPort: n,
			})
		}(i + 1000)
	}
	wg.Wait()
}
