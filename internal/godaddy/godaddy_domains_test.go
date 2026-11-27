package godaddy

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func domainsServer(t *testing.T, domains []Domain) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(domains) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestListDomainsSorted_HidesInactiveByDefault(t *testing.T) {
	srv := domainsServer(t, []Domain{
		{Domain: "zeta.io", Status: "ACTIVE"},
		{Domain: "old.com", Status: "EXPIRED"},
		{Domain: "Alpha.com", Status: "active"},
		{Domain: "gone.net", Status: "TRANSFERRED_OUT"},
		{Domain: "bye.org", Status: "CANCELLED"},
	})
	c := newTestClient(srv)

	got, err := c.ListDomainsSorted(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Domain != "Alpha.com" || got[1].Domain != "zeta.io" {
		t.Fatalf("want [Alpha.com zeta.io], got %+v", got)
	}

	all, err := c.ListDomainsSorted(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 5 || all[0].Domain != "Alpha.com" || all[1].Domain != "bye.org" {
		t.Fatalf("want all 5 sorted, got %+v", all)
	}
}

func TestUpdateConfig_ChangesBaseURLAndCredentials(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Write([]byte("[]")) //nolint:errcheck
	}))
	defer srv.Close()

	c := NewClient("k", "s", "https://unused.invalid", silentLogger())
	c.UpdateConfig("k2", "s2", srv.URL+"/")
	if c.BaseURL() != srv.URL {
		t.Fatalf("trailing slash should be trimmed, got %q", c.BaseURL())
	}
	if _, err := c.ListDomains(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "sso-key k2:s2" {
		t.Errorf("auth header: got %q", gotAuth)
	}
}

func TestClient_ConcurrentUpdateAndRequest(t *testing.T) {
	srv := domainsServer(t, nil)
	c := newTestClient(srv)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); c.UpdateConfig("a", "b", srv.URL) }()
		go func() { defer wg.Done(); _, _ = c.ListDomains(context.Background()); _ = c.IsConfigured() }()
	}
	wg.Wait()
}
