// Tests for the acme package.
package acme

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.Level(999)}))
}

// ─── NewClient ────────────────────────────────────────────────────────────────

func TestNewClient_CreatesClientSuccessfully(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if client == nil {
		t.Error("NewClient returned nil client")
	}
}

func TestNewClient_CreatesAccountKey(t *testing.T) {
	dir := t.TempDir()
	_, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	// Account key file should exist
	keyPath := filepath.Join(dir, "account.key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Error("account.key should have been created by NewClient")
	}
}

func TestNewClient_ReusesExistingAccountKey(t *testing.T) {
	dir := t.TempDir()
	// Create first client — generates key
	c1, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("first NewClient: %v", err)
	}
	// Create second client — should reuse existing key
	c2, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("second NewClient: %v", err)
	}
	if c1 == nil || c2 == nil {
		t.Fatal("clients should not be nil")
	}
}

func TestNewClient_InvalidCertDir_ReturnsError(t *testing.T) {
	// Try to create in a path that can't be created (file exists where dir should be)
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocked")
	if err := os.WriteFile(blocker, []byte("not a dir"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	// Try to create certDir at a path that has a file blocking it
	nestedPath := filepath.Join(blocker, "certs")
	_, err := NewClient("test@example.com", nestedPath, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err == nil {
		t.Error("NewClient with invalid certDir should return error")
	}
}

// ─── GetAllChallenges ─────────────────────────────────────────────────────────

func TestGetAllChallenges_EmptyInitially(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	challenges := client.GetAllChallenges()
	if len(challenges) != 0 {
		t.Errorf("initial challenges: want 0, got %d", len(challenges))
	}
}

// ─── GetChallengeStatus ───────────────────────────────────────────────────────

func TestGetChallengeStatus_ReturnsNilWhenNoPendingChallenge(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient("test@example.com", dir, "https://acme-staging-v02.api.letsencrypt.org/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	status := client.GetChallengeStatus("unknown.example.com")
	if status != nil {
		t.Errorf("GetChallengeStatus for unknown domain: want nil, got %+v", status)
	}
}

// ─── Register ─────────────────────────────────────────────────────────────────

func TestRegister_FailsWithoutACMEServer(t *testing.T) {
	dir := t.TempDir()
	// Use a non-existent directory URL so the request fails
	client, err := NewClient("test@example.com", dir, "http://127.0.0.1:0/acme/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	err = client.Register(context.Background())
	if err == nil {
		t.Error("Register to non-existent server should return error")
	}
}

// ─── loadOrCreateAccountKey ───────────────────────────────────────────────────

func TestLoadOrCreateAccountKey_CreatesNewKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	key, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("loadOrCreateAccountKey: %v", err)
	}
	if key == nil {
		t.Error("returned key should not be nil")
	}
	// Key file should now exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Error("key file should have been created")
	}
}

func TestLoadOrCreateAccountKey_LoadsExistingKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	// Create key first
	key1, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Load again
	key2, err := loadOrCreateAccountKey(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if key1 == nil || key2 == nil {
		t.Error("keys should not be nil")
	}
}

func TestLoadOrCreateAccountKey_FailsOnInvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "account.key")
	// Write invalid PEM data
	if err := os.WriteFile(path, []byte("not valid PEM data"), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}
	_, err := loadOrCreateAccountKey(path)
	if err == nil {
		t.Error("loadOrCreateAccountKey with invalid PEM should return error")
	}
}

// ─── RequestCertificate ───────────────────────────────────────────────────────

func TestRequestCertificate_AuthorizeOrderFails(t *testing.T) {
	dir := t.TempDir()
	// Use a non-existent local endpoint so AuthorizeOrder fails immediately.
	client, err := NewClient("test@example.com", dir, "http://127.0.0.1:1/acme/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, err = client.RequestCertificate(context.Background(), "example.com")
	if err == nil {
		t.Error("RequestCertificate to non-existent ACME server should return error")
	}
}

// ─── CompleteChallengeAndFetchCert ────────────────────────────────────────────

func TestCompleteChallengeAndFetchCert_NoPendingChallenge(t *testing.T) {
	dir := t.TempDir()
	client, err := NewClient("test@example.com", dir, "http://127.0.0.1:1/acme/directory", silentLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, _, err = client.CompleteChallengeAndFetchCert(context.Background(), "no-challenge.example.com")
	if err == nil {
		t.Error("CompleteChallengeAndFetchCert without pending challenge should return error")
	}
	if err.Error() != "no pending challenge for no-challenge.example.com" {
		t.Errorf("unexpected error: %v", err)
	}
}
