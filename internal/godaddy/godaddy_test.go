// Tests for the GoDaddy DNS client.
// This file lives in package godaddy (not godaddy_test) so it can reach the
// unexported extractBaseDomain helper.
package godaddy

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ─── Helpers ──────────────────────────────────────────────────────────────────

func silentLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError + 4}))
}

// newTestClient creates a Client pointed at the given test server.
func newTestClient(srv *httptest.Server) *Client {
	return NewClient("test-key", "test-secret", srv.URL, silentLogger())
}

// ─── extractBaseDomain ───────────────────────────────────────────────────────

func TestExtractBaseDomain(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"deep.sub.example.com", "example.com"},
		{"*.example.com", "example.com"},
		{"_acme-challenge.example.com", "example.com"},
		{"_acme-challenge.sub.example.com", "example.com"},
		{"simply.testdomain.io", "testdomain.io"},
		{"_acme-challenge.simply.testdomain.io", "testdomain.io"},
		{"example.co.uk", "co.uk"}, // simple two-label extraction
	}

	for _, tc := range tests {
		got := extractBaseDomain(tc.in)
		if got != tc.want {
			t.Errorf("extractBaseDomain(%q): want %q, got %q", tc.in, tc.want, got)
		}
	}
}

// ─── IsConfigured ─────────────────────────────────────────────────────────────

func TestIsConfigured_ReturnsFalseWhenEmpty(t *testing.T) {
	c := NewClient("", "", "https://api.godaddy.com", silentLogger())
	if c.IsConfigured() {
		t.Error("IsConfigured() should be false when credentials are empty")
	}
}

func TestIsConfigured_ReturnsTrueWithCredentials(t *testing.T) {
	c := NewClient("key", "secret", "https://api.godaddy.com", silentLogger())
	if !c.IsConfigured() {
		t.Error("IsConfigured() should be true when both key and secret are set")
	}
}

func TestIsConfigured_ReturnsFalseWithOnlyKey(t *testing.T) {
	c := NewClient("key", "", "https://api.godaddy.com", silentLogger())
	if c.IsConfigured() {
		t.Error("IsConfigured() should be false when secret is empty")
	}
}

// ─── UpdateCredentials ────────────────────────────────────────────────────────

func TestUpdateCredentials_ChangesIsConfigured(t *testing.T) {
	c := NewClient("", "", "https://api.godaddy.com", silentLogger())
	if c.IsConfigured() {
		t.Fatal("pre-condition: should not be configured")
	}
	c.UpdateCredentials("new-key", "new-secret")
	if !c.IsConfigured() {
		t.Error("should be configured after UpdateCredentials")
	}
}

// ─── doRequest — auth header ─────────────────────────────────────────────────

func TestDoRequest_SetsAuthorizationHeader(t *testing.T) {
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("[]")) //nolint:errcheck
	}))
	defer srv.Close()

	c := NewClient("mykey", "mysecret", srv.URL, silentLogger())
	c.ListDomains(context.Background()) //nolint:errcheck

	want := "sso-key mykey:mysecret"
	if gotHeader != want {
		t.Errorf("Authorization header: want %q, got %q", want, gotHeader)
	}
}

func TestDoRequest_ReturnsErrorOn4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"UNABLE_TO_AUTHENTICATE"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.ListDomains(context.Background())
	if err == nil {
		t.Error("expected error for 401 response, got nil")
	}
}

func TestDoRequest_ReturnsErrorOn5xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal server error")) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.ListDomains(context.Background())
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

// ─── ListDomains ──────────────────────────────────────────────────────────────

func TestListDomains_ParsesResponse(t *testing.T) {
	domains := []Domain{
		{Domain: "example.com", Status: "ACTIVE"},
		{Domain: "foo.io", Status: "ACTIVE"},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/domains" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: %s", r.Method)
		}
		json.NewEncoder(w).Encode(domains) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatalf("ListDomains: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 domains, got %d", len(got))
	}
	if got[0].Domain != "example.com" {
		t.Errorf("domain[0]: want example.com, got %s", got[0].Domain)
	}
}

// ─── CreateRecord ─────────────────────────────────────────────────────────────

func TestCreateRecord_UsesPATCH(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.CreateRecord(context.Background(), "example.com", DNSRecord{Type: "A", Name: "sub", Data: "1.2.3.4", TTL: 600}) //nolint:errcheck

	if gotMethod != http.MethodPatch {
		t.Errorf("CreateRecord should use PATCH, got %s", gotMethod)
	}
}

func TestCreateRecord_SendsRecordAsArray(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.CreateRecord(context.Background(), "example.com", DNSRecord{Type: "TXT", Name: "_test", Data: "val", TTL: 600}) //nolint:errcheck

	var records []DNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		t.Fatalf("request body is not a JSON array: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record in body, got %d", len(records))
	}
	if records[0].Type != "TXT" {
		t.Errorf("record type: want TXT, got %s", records[0].Type)
	}
}

// ─── CreateTXTRecord ──────────────────────────────────────────────────────────

func TestCreateTXTRecord_UsesRelativeNameForGoDaddy(t *testing.T) {
	// The GoDaddy API expects record names relative to the zone (base domain).
	// e.g. "_acme-challenge.simply" not "_acme-challenge.simply.testdomain.io"
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	// Simulates what ACME handler passes: fullDomain="simply.testdomain.io",
	// name="_acme-challenge.simply.testdomain.io" (absolute FQDN).
	err := c.CreateTXTRecord(context.Background(), "simply.testdomain.io", "_acme-challenge.simply.testdomain.io", "token123")
	if err != nil {
		t.Fatalf("CreateTXTRecord: %v", err)
	}

	var records []DNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		t.Fatalf("request body: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	// Should be relative: "_acme-challenge.simply" not the full FQDN.
	if strings.Contains(records[0].Name, ".testdomain.io") {
		t.Errorf("record name should be relative to zone, got %q", records[0].Name)
	}
	if records[0].Name != "_acme-challenge.simply" {
		t.Errorf("record name: want _acme-challenge.simply, got %q", records[0].Name)
	}
	if records[0].Data != "token123" {
		t.Errorf("record data: want token123, got %q", records[0].Data)
	}
	if records[0].Type != "TXT" {
		t.Errorf("record type: want TXT, got %s", records[0].Type)
	}
}

func TestCreateTXTRecord_HitsCorrectPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.CreateTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com", "val") //nolint:errcheck

	wantPath := "/v1/domains/example.com/records"
	if gotPath != wantPath {
		t.Errorf("path: want %s, got %s", wantPath, gotPath)
	}
}

// ─── DeleteRecord ─────────────────────────────────────────────────────────────

func TestDeleteRecord_UsesDELETE(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.DeleteRecord(context.Background(), "example.com", "TXT", "_acme-challenge") //nolint:errcheck

	if gotMethod != http.MethodDelete {
		t.Errorf("method: want DELETE, got %s", gotMethod)
	}
	wantPath := "/v1/domains/example.com/records/TXT/_acme-challenge"
	if gotPath != wantPath {
		t.Errorf("path: want %s, got %s", wantPath, gotPath)
	}
}

// ─── VerifyConnection ─────────────────────────────────────────────────────────

func TestVerifyConnection_SucceedsOn200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]Domain{{Domain: "example.com", Status: "ACTIVE"}}) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.VerifyConnection(context.Background()); err != nil {
		t.Errorf("VerifyConnection: want nil, got %v", err)
	}
}

func TestVerifyConnection_FailsOnAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"message":"UNABLE_TO_AUTHENTICATE"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if err := c.VerifyConnection(context.Background()); err == nil {
		t.Error("VerifyConnection: want error for 401, got nil")
	}
}
