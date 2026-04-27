// Extra tests to lift godaddy coverage.
package godaddy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ─── NewClient ────────────────────────────────────────────────────────────────

func TestNewClient_EmptyBaseURL_UsesDefault(t *testing.T) {
	c := NewClient("key", "secret", "", silentLogger())
	if c.baseURL != "https://api.godaddy.com" {
		t.Errorf("baseURL: want https://api.godaddy.com, got %s", c.baseURL)
	}
	if !c.IsConfigured() {
		t.Error("client should be configured with key and secret")
	}
}

// ─── GetRecords ───────────────────────────────────────────────────────────────

func TestGetRecords_ParsesResponse(t *testing.T) {
	records := []DNSRecord{
		{Type: "A", Name: "@", Data: "1.2.3.4", TTL: 600},
		{Type: "CNAME", Name: "www", Data: "example.com", TTL: 3600},
	}
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewEncoder(w).Encode(records) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	got, err := c.GetRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("GetRecords: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 records, got %d", len(got))
	}
	if got[0].Type != "A" {
		t.Errorf("record[0].Type: want A, got %s", got[0].Type)
	}
	if gotPath != "/v1/domains/example.com/records" {
		t.Errorf("path: want /v1/domains/example.com/records, got %s", gotPath)
	}
}

func TestGetRecords_ErrorOnAPIFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error")) //nolint:errcheck
	}))
	defer srv.Close()

	c := newTestClient(srv)
	_, err := c.GetRecords(context.Background(), "example.com")
	if err == nil {
		t.Error("expected error for 500 response, got nil")
	}
}

// ─── UpdateRecord ─────────────────────────────────────────────────────────────

func TestUpdateRecord_UsesPUT(t *testing.T) {
	var gotMethod string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.UpdateRecord(context.Background(), "example.com", "A", "sub", DNSRecord{Type: "A", Name: "sub", Data: "1.2.3.4", TTL: 600}) //nolint:errcheck

	if gotMethod != http.MethodPut {
		t.Errorf("UpdateRecord should use PUT, got %s", gotMethod)
	}
}

func TestUpdateRecord_CorrectPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.UpdateRecord(context.Background(), "example.com", "A", "sub", DNSRecord{Type: "A", Name: "sub", Data: "1.2.3.4", TTL: 600}) //nolint:errcheck

	want := "/v1/domains/example.com/records/A/sub"
	if gotPath != want {
		t.Errorf("path: want %s, got %s", want, gotPath)
	}
}

func TestUpdateRecord_SendsRecordInArray(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.UpdateRecord(context.Background(), "example.com", "A", "sub", DNSRecord{Type: "A", Name: "sub", Data: "5.6.7.8", TTL: 600}) //nolint:errcheck

	var records []DNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		t.Fatalf("body is not a JSON array: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record in body, got %d", len(records))
	}
	if records[0].Data != "5.6.7.8" {
		t.Errorf("record.Data: want 5.6.7.8, got %s", records[0].Data)
	}
}

// ─── DeleteTXTRecord ──────────────────────────────────────────────────────────

func TestDeleteTXTRecord_CallsDeleteRecord(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.DeleteTXTRecord(context.Background(), "example.com", "_acme-challenge.example.com")
	if err != nil {
		t.Fatalf("DeleteTXTRecord: %v", err)
	}

	if gotMethod != http.MethodDelete {
		t.Errorf("method: want DELETE, got %s", gotMethod)
	}
	// The record name "_acme-challenge.example.com" should be made relative:
	// "_acme-challenge" (stripping ".example.com")
	wantPath := "/v1/domains/example.com/records/TXT/_acme-challenge"
	if gotPath != wantPath {
		t.Errorf("path: want %s, got %s", wantPath, gotPath)
	}
}

// ─── CreateARecord ────────────────────────────────────────────────────────────

func TestCreateARecord_CreatesAType(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.CreateARecord(context.Background(), "example.com", "www", "1.2.3.4")
	if err != nil {
		t.Fatalf("CreateARecord: %v", err)
	}

	var records []DNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		t.Fatalf("body is not a JSON array: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	if records[0].Type != "A" {
		t.Errorf("Type: want A, got %s", records[0].Type)
	}
	if records[0].Data != "1.2.3.4" {
		t.Errorf("Data: want 1.2.3.4, got %s", records[0].Data)
	}
	if records[0].Name != "www" {
		t.Errorf("Name: want www, got %s", records[0].Name)
	}
}

// ─── CreateCNAMERecord ────────────────────────────────────────────────────────

func TestCreateCNAMERecord_CreatesCNAMEType(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	err := c.CreateCNAMERecord(context.Background(), "example.com", "blog", "target.example.com")
	if err != nil {
		t.Fatalf("CreateCNAMERecord: %v", err)
	}

	var records []DNSRecord
	if err := json.Unmarshal(body, &records); err != nil {
		t.Fatalf("body is not a JSON array: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("want 1 record, got %d", len(records))
	}
	if records[0].Type != "CNAME" {
		t.Errorf("Type: want CNAME, got %s", records[0].Type)
	}
	if records[0].Data != "target.example.com" {
		t.Errorf("Data: want target.example.com, got %s", records[0].Data)
	}
	if records[0].Name != "blog" {
		t.Errorf("Name: want blog, got %s", records[0].Name)
	}
}
