package config_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/gcis/proxygate/internal/config"
)

func newOpsManager(t *testing.T) *config.Manager {
	t.Helper()
	t.Setenv("PROXYGATE_CONFIG_KEY", "")
	m, err := config.NewManager(filepath.Join(t.TempDir(), "cfg.json"))
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	return m
}

func TestCreateRoute_ReturnsStoredRouteWithIDAndTimestamps(t *testing.T) {
	m := newOpsManager(t)
	got, err := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com", TargetHost: "127.0.0.1", TargetPort: 80})
	if err != nil {
		t.Fatalf("CreateRoute: %v", err)
	}
	if got.ID == "" || got.CreatedAt == "" || got.UpdatedAt == "" {
		t.Fatalf("want ID and timestamps populated, got %+v", got)
	}
	if stored := m.GetRoute(got.ID); stored == nil || stored.Domain != "a.example.com" {
		t.Fatalf("route not persisted: %+v", stored)
	}
}

func TestCreateRoute_RejectsDomainPrefixCollision(t *testing.T) {
	m := newOpsManager(t)
	if _, err := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com", PathPrefix: "/api"}); err != nil {
		t.Fatal(err)
	}
	_, err := m.CreateRoute(config.ProxyRoute{Domain: "A.Example.com", PathPrefix: "/api"})
	if !errors.Is(err, config.ErrRouteConflict) {
		t.Fatalf("want ErrRouteConflict, got %v", err)
	}
	// Different prefix on same domain is fine.
	if _, err := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com"}); err != nil {
		t.Fatalf("catch-all on same domain should be allowed: %v", err)
	}
	if n := len(m.Get().Routes); n != 2 {
		t.Fatalf("want 2 routes, got %d", n)
	}
}

func TestModifyRoute_MergesAndPreservesIdentity(t *testing.T) {
	m := newOpsManager(t)
	orig, _ := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com", TargetPort: 80, CertFile: "c.pem", PathPrefix: "/x"})

	got, err := m.ModifyRoute(orig.ID, func(r *config.ProxyRoute) error {
		r.TargetPort = 81
		r.ID = "hijack"
		return nil
	})
	if err != nil {
		t.Fatalf("ModifyRoute: %v", err)
	}
	if got.ID != orig.ID || got.CreatedAt != orig.CreatedAt {
		t.Errorf("identity not preserved: %+v", got)
	}
	if got.TargetPort != 81 || got.CertFile != "c.pem" || got.PathPrefix != "/x" {
		t.Errorf("merge wrong: %+v", got)
	}
}

func TestModifyRoute_NotFoundAndConflict(t *testing.T) {
	m := newOpsManager(t)
	if _, err := m.ModifyRoute("nope", func(*config.ProxyRoute) error { return nil }); !errors.Is(err, config.ErrRouteNotFound) {
		t.Fatalf("want ErrRouteNotFound, got %v", err)
	}
	a, _ := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com"})
	_, _ = m.CreateRoute(config.ProxyRoute{Domain: "b.example.com"})
	_, err := m.ModifyRoute(a.ID, func(r *config.ProxyRoute) error { r.Domain = "b.example.com"; return nil })
	if !errors.Is(err, config.ErrRouteConflict) {
		t.Fatalf("want ErrRouteConflict, got %v", err)
	}
	if m.GetRoute(a.ID).Domain != "a.example.com" {
		t.Error("route must be unchanged after a rejected modification")
	}
}

func TestModifyRoute_CallbackErrorLeavesRouteUntouched(t *testing.T) {
	m := newOpsManager(t)
	a, _ := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com", TargetPort: 80})
	boom := errors.New("boom")
	_, err := m.ModifyRoute(a.ID, func(r *config.ProxyRoute) error { r.TargetPort = 99; return boom })
	if !errors.Is(err, boom) {
		t.Fatalf("want boom, got %v", err)
	}
	if m.GetRoute(a.ID).TargetPort != 80 {
		t.Error("route must be unchanged")
	}
}

func TestRemoveRoute(t *testing.T) {
	m := newOpsManager(t)
	a, _ := m.CreateRoute(config.ProxyRoute{Domain: "a.example.com"})
	if err := m.RemoveRoute(a.ID); err != nil {
		t.Fatalf("RemoveRoute: %v", err)
	}
	if err := m.RemoveRoute(a.ID); !errors.Is(err, config.ErrRouteNotFound) {
		t.Fatalf("second remove: want ErrRouteNotFound, got %v", err)
	}
}
