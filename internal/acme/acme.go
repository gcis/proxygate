// Package acme provides Let's Encrypt certificate management with DNS-01 challenge support.
package acme

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/acme"
)

type ChallengeStatus struct {
	Domain     string `json:"domain"`
	Status     string `json:"status"` // pending, ready, processing, valid, invalid
	RecordName string `json:"record_name,omitempty"`
	RecordVal  string `json:"record_value,omitempty"`
	Error      string `json:"error,omitempty"`
}

type DNSProvider interface {
	CreateTXTRecord(ctx context.Context, domain, name, value string) error
	DeleteTXTRecord(ctx context.Context, domain, name string) error
}

type Client struct {
	mu         sync.Mutex
	acmeClient *acme.Client
	accountKey crypto.Signer
	certDir    string
	email      string
	directory  string
	logger     *slog.Logger
	challenges map[string]*ChallengeStatus
}

func NewClient(email, certDir, directory string, logger *slog.Logger) (*Client, error) {
	if err := os.MkdirAll(certDir, 0700); err != nil {
		return nil, fmt.Errorf("creating cert dir: %w", err)
	}

	key, err := loadOrCreateAccountKey(filepath.Join(certDir, "account.key"))
	if err != nil {
		return nil, fmt.Errorf("account key: %w", err)
	}

	client := &acme.Client{
		Key:          key,
		DirectoryURL: directory,
	}

	return &Client{
		acmeClient: client,
		accountKey: key,
		certDir:    certDir,
		email:      email,
		directory:  directory,
		logger:     logger,
		challenges: make(map[string]*ChallengeStatus),
	}, nil
}

func loadOrCreateAccountKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("invalid PEM data in account key")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing account key: %w", err)
		}
		return key, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating account key: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshaling account key: %w", err)
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0600); err != nil {
		return nil, fmt.Errorf("saving account key: %w", err)
	}

	return key, nil
}

func (c *Client) Register(ctx context.Context) error {
	acct := &acme.Account{
		Contact: []string{"mailto:" + c.email},
	}

	_, err := c.acmeClient.Register(ctx, acct, func(tosURL string) bool {
		c.logger.Info("accepting ACME ToS", "url", tosURL)
		return true
	})
	if err != nil && err != acme.ErrAccountAlreadyExists {
		return fmt.Errorf("registering account: %w", err)
	}

	c.logger.Info("ACME account registered", "email", c.email)
	return nil
}

// RequestCertificate initiates a DNS-01 challenge for the domain.
// Returns the DNS record that needs to be created.
func (c *Client) RequestCertificate(ctx context.Context, domain string) (*ChallengeStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.Info("requesting certificate", "domain", domain)

	// Create order
	order, err := c.acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		return nil, fmt.Errorf("authorizing order: %w", err)
	}

	if len(order.AuthzURLs) == 0 {
		return nil, fmt.Errorf("no authorization URLs returned")
	}

	// Get authorization
	authz, err := c.acmeClient.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		return nil, fmt.Errorf("getting authorization: %w", err)
	}

	// Find DNS-01 challenge
	var dnsChallenge *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dnsChallenge = ch
			break
		}
	}

	if dnsChallenge == nil {
		return nil, fmt.Errorf("DNS-01 challenge not available")
	}

	// Get DNS record value
	recordValue, err := c.acmeClient.DNS01ChallengeRecord(dnsChallenge.Token)
	if err != nil {
		return nil, fmt.Errorf("computing DNS record: %w", err)
	}

	recordName := "_acme-challenge." + domain

	status := &ChallengeStatus{
		Domain:     domain,
		Status:     "pending",
		RecordName: recordName,
		RecordVal:  recordValue,
	}
	c.challenges[domain] = status

	c.logger.Info("DNS-01 challenge ready",
		"domain", domain,
		"record_name", recordName,
		"record_value", recordValue,
	)

	return status, nil
}

// CompleteChallengeAndFetchCert tells ACME the DNS record is ready, waits for validation,
// and fetches the certificate.
func (c *Client) CompleteChallengeAndFetchCert(ctx context.Context, domain string) (certPath, keyPath string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.logger.Info("completing challenge", "domain", domain)

	status, ok := c.challenges[domain]
	if !ok {
		return "", "", fmt.Errorf("no pending challenge for %s", domain)
	}

	// Re-authorize to get fresh state
	order, err := c.acmeClient.AuthorizeOrder(ctx, acme.DomainIDs(domain))
	if err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("re-authorizing order: %w", err)
	}

	authz, err := c.acmeClient.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("getting authorization: %w", err)
	}

	var dnsChallenge *acme.Challenge
	for _, ch := range authz.Challenges {
		if ch.Type == "dns-01" {
			dnsChallenge = ch
			break
		}
	}

	if dnsChallenge == nil {
		return "", "", fmt.Errorf("DNS-01 challenge not found")
	}

	// Accept the challenge
	status.Status = "processing"
	if _, err := c.acmeClient.Accept(ctx, dnsChallenge); err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("accepting challenge: %w", err)
	}

	// Wait for authorization
	if _, err := c.acmeClient.WaitAuthorization(ctx, order.AuthzURLs[0]); err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("waiting for authorization: %w", err)
	}

	// Generate certificate key
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generating cert key: %w", err)
	}

	// Create CSR
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		DNSNames: []string{domain},
	}, certKey)
	if err != nil {
		return "", "", fmt.Errorf("creating CSR: %w", err)
	}

	// Wait for order readiness
	order, err = c.acmeClient.WaitOrder(ctx, order.URI)
	if err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("waiting for order: %w", err)
	}

	// Finalize order
	derChain, _, err := c.acmeClient.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		status.Status = "invalid"
		status.Error = err.Error()
		return "", "", fmt.Errorf("creating certificate: %w", err)
	}

	// Save certificate
	certPath = filepath.Join(c.certDir, domain+".pem")
	keyPath = filepath.Join(c.certDir, domain+".key")

	certFile, err := os.Create(certPath)
	if err != nil {
		return "", "", fmt.Errorf("creating cert file: %w", err)
	}
	defer certFile.Close()

	for _, der := range derChain {
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
			return "", "", fmt.Errorf("encoding certificate: %w", err)
		}
	}

	keyDer, err := x509.MarshalECPrivateKey(certKey)
	if err != nil {
		return "", "", fmt.Errorf("marshaling key: %w", err)
	}

	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer})
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		return "", "", fmt.Errorf("writing key file: %w", err)
	}

	status.Status = "valid"
	c.logger.Info("certificate obtained", "domain", domain, "cert", certPath, "key", keyPath)

	return certPath, keyPath, nil
}

func (c *Client) GetChallengeStatus(domain string) *ChallengeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	if status, ok := c.challenges[domain]; ok {
		cp := *status
		return &cp
	}
	return nil
}

func (c *Client) GetAllChallenges() []ChallengeStatus {
	c.mu.Lock()
	defer c.mu.Unlock()

	result := make([]ChallengeStatus, 0, len(c.challenges))
	for _, s := range c.challenges {
		result = append(result, *s)
	}
	return result
}
