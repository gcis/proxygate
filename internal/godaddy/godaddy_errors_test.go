package godaddy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRequestErrors(t *testing.T) {
	ctx := context.Background()
	down := NewClient("k", "s", "http://127.0.0.1:1", silentLogger())
	if _, err := down.ListDomains(ctx); err == nil {
		t.Error("unreachable API must fail")
	}
	if err := down.CreateRecord(ctx, "example.com", DNSRecord{Type: "A", Name: "x", Data: "1.2.3.4"}); err == nil {
		t.Error("CreateRecord to unreachable API must fail")
	}
	if err := down.UpdateRecord(ctx, "example.com", "A", "x", DNSRecord{Data: "1.2.3.4"}); err == nil {
		t.Error("UpdateRecord to unreachable API must fail")
	}
	if err := down.DeleteRecord(ctx, "example.com", "A", "x"); err == nil {
		t.Error("DeleteRecord to unreachable API must fail")
	}
	if _, err := down.ListDomainsSorted(ctx, false); err == nil {
		t.Error("ListDomainsSorted must propagate errors")
	}

	bad := NewClient("k", "s", "http://[::1", silentLogger()) // invalid URL
	if _, err := bad.GetRecords(ctx, "example.com"); err == nil {
		t.Error("invalid base URL must fail")
	}

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json")) })) //nolint:errcheck
	defer garbage.Close()
	g := NewClient("k", "s", garbage.URL, silentLogger())
	if _, err := g.ListDomains(ctx); err == nil {
		t.Error("non-JSON domains must fail")
	}
	if _, err := g.GetRecords(ctx, "example.com"); err == nil {
		t.Error("non-JSON records must fail")
	}

	if _, err := (&Client{baseURL: "http://x", client: http.DefaultClient}).doRequest(ctx, http.MethodPost, "/", func() {}); err == nil {
		t.Error("unmarshalable body must fail")
	}
}

func TestExtractBaseDomain_Short(t *testing.T) {
	if got := extractBaseDomain("localhost"); got != "localhost" {
		t.Errorf("single label: %q", got)
	}
}
