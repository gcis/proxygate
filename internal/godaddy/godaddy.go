// Package godaddy provides GoDaddy DNS API integration for managing DNS records.
package godaddy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     string `json:"data"`
	TTL      int    `json:"ttl"`
	Priority int    `json:"priority,omitempty"`
}

type Domain struct {
	Domain    string `json:"domain"`
	Status    string `json:"status"`
	ExpiresAt string `json:"expires"`
}

type Client struct {
	mu        sync.RWMutex
	apiKey    string
	apiSecret string
	baseURL   string
	client    *http.Client
	logger    *slog.Logger
}

func NewClient(apiKey, apiSecret, baseURL string, logger *slog.Logger) *Client {
	if baseURL == "" {
		baseURL = "https://api.godaddy.com"
	}
	return &Client{
		apiKey:    apiKey,
		apiSecret: apiSecret,
		baseURL:   baseURL,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		logger: logger,
	}
}

func (c *Client) IsConfigured() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.apiKey != "" && c.apiSecret != ""
}

func (c *Client) UpdateCredentials(apiKey, apiSecret string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = apiKey
	c.apiSecret = apiSecret
}

// UpdateConfig replaces credentials and, when baseURL is non-empty, the API
// endpoint. Safe to call while requests are in flight.
func (c *Client) UpdateConfig(apiKey, apiSecret, baseURL string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.apiKey = apiKey
	c.apiSecret = apiSecret
	if baseURL != "" {
		c.baseURL = strings.TrimRight(baseURL, "/")
	}
}

// BaseURL returns the API endpoint currently in use.
func (c *Client) BaseURL() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.baseURL
}

func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshaling request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	c.mu.RLock()
	baseURL, apiKey, apiSecret := c.baseURL, c.apiKey, c.apiSecret
	c.mu.RUnlock()

	req, err := http.NewRequestWithContext(ctx, method, baseURL+path, reqBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("sso-key %s:%s", apiKey, apiSecret))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func (c *Client) ListDomains(ctx context.Context) ([]Domain, error) {
	data, err := c.doRequest(ctx, http.MethodGet, "/v1/domains", nil)
	if err != nil {
		return nil, err
	}

	var domains []Domain
	if err := json.Unmarshal(data, &domains); err != nil {
		return nil, fmt.Errorf("parsing domains: %w", err)
	}

	return domains, nil
}

// ListDomainsSorted returns the account's domains sorted by name. Unless
// includeInactive is set, only ACTIVE domains are returned — expired,
// cancelled, transferred-out and pending domains cannot have their DNS
// managed, so listing them by default is just noise.
func (c *Client) ListDomainsSorted(ctx context.Context, includeInactive bool) ([]Domain, error) {
	domains, err := c.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]Domain, 0, len(domains))
	for _, d := range domains {
		if includeInactive || IsActive(d) {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Domain) < strings.ToLower(out[j].Domain)
	})
	return out, nil
}

// IsActive reports whether GoDaddy lists the domain with status ACTIVE.
func IsActive(d Domain) bool {
	return strings.EqualFold(strings.TrimSpace(d.Status), "ACTIVE")
}

func (c *Client) GetRecords(ctx context.Context, domain string) ([]DNSRecord, error) {
	path := fmt.Sprintf("/v1/domains/%s/records", domain)
	data, err := c.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var records []DNSRecord
	if err := json.Unmarshal(data, &records); err != nil {
		return nil, fmt.Errorf("parsing records: %w", err)
	}

	return records, nil
}

func (c *Client) CreateRecord(ctx context.Context, domain string, record DNSRecord) error {
	path := fmt.Sprintf("/v1/domains/%s/records", domain)
	records := []DNSRecord{record}

	_, err := c.doRequest(ctx, http.MethodPatch, path, records)
	if err != nil {
		return fmt.Errorf("creating record: %w", err)
	}

	c.logger.Info("DNS record created",
		"domain", domain,
		"type", record.Type,
		"name", record.Name,
		"data", record.Data,
	)
	return nil
}

func (c *Client) UpdateRecord(ctx context.Context, domain, recordType, name string, record DNSRecord) error {
	path := fmt.Sprintf("/v1/domains/%s/records/%s/%s", domain, recordType, name)
	records := []DNSRecord{record}

	_, err := c.doRequest(ctx, http.MethodPut, path, records)
	if err != nil {
		return fmt.Errorf("updating record: %w", err)
	}

	c.logger.Info("DNS record updated",
		"domain", domain,
		"type", recordType,
		"name", name,
	)
	return nil
}

func (c *Client) DeleteRecord(ctx context.Context, domain, recordType, name string) error {
	path := fmt.Sprintf("/v1/domains/%s/records/%s/%s", domain, recordType, name)

	_, err := c.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return fmt.Errorf("deleting record: %w", err)
	}

	c.logger.Info("DNS record deleted",
		"domain", domain,
		"type", recordType,
		"name", name,
	)
	return nil
}

// CreateTXTRecord implements the acme.DNSProvider interface for ACME DNS-01 challenges.
func (c *Client) CreateTXTRecord(ctx context.Context, fullDomain, name, value string) error {
	// Extract the base domain from the full domain
	baseDomain := extractBaseDomain(fullDomain)

	// GoDaddy API expects record names relative to the base domain.
	// Convert absolute FQDN (e.g. "_acme-challenge.app.example.io") to relative
	// (e.g. "_acme-challenge.app") by stripping the ".baseDomain" suffix.
	relName := strings.TrimSuffix(name, "."+baseDomain)

	record := DNSRecord{
		Type: "TXT",
		Name: relName,
		Data: value,
		TTL:  600,
	}

	c.logger.Info("creating ACME TXT record",
		"base_domain", baseDomain,
		"name", relName,
		"abs_name", name,
	)

	return c.CreateRecord(ctx, baseDomain, record)
}

// DeleteTXTRecord implements the acme.DNSProvider interface.
func (c *Client) DeleteTXTRecord(ctx context.Context, fullDomain, name string) error {
	baseDomain := extractBaseDomain(fullDomain)
	relName := strings.TrimSuffix(name, "."+baseDomain)
	return c.DeleteRecord(ctx, baseDomain, "TXT", relName)
}

// CreateARecord creates an A record pointing to the given IP.
func (c *Client) CreateARecord(ctx context.Context, domain, subdomain, ip string) error {
	record := DNSRecord{
		Type: "A",
		Name: subdomain,
		Data: ip,
		TTL:  600,
	}
	return c.CreateRecord(ctx, domain, record)
}

// CreateCNAMERecord creates a CNAME record.
func (c *Client) CreateCNAMERecord(ctx context.Context, domain, subdomain, target string) error {
	record := DNSRecord{
		Type: "CNAME",
		Name: subdomain,
		Data: target,
		TTL:  3600,
	}
	return c.CreateRecord(ctx, domain, record)
}

func extractBaseDomain(domain string) string {
	// Remove leading wildcards or _acme-challenge prefix
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, "_acme-challenge.")

	parts := strings.Split(domain, ".")
	if len(parts) >= 2 {
		return strings.Join(parts[len(parts)-2:], ".")
	}
	return domain
}

// VerifyConnection tests the GoDaddy API credentials.
func (c *Client) VerifyConnection(ctx context.Context) error {
	_, err := c.ListDomains(ctx)
	if err != nil {
		return fmt.Errorf("credential verification failed: %w", err)
	}
	return nil
}
