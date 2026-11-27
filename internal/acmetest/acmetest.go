// Package acmetest is an in-process fake ACME (RFC 8555) server for tests.
// It speaks just enough of the protocol for golang.org/x/crypto/acme:
// directory, nonces, accounts, orders, DNS-01 authorizations, finalize and
// certificate download. Requests are not signature-checked. Certificates
// are real, signed by a throwaway CA, so callers can load and inspect them.
package acmetest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server is a running fake ACME CA.
type Server struct {
	*httptest.Server

	// FailValidation makes every accepted challenge end in an invalid
	// authorization, as when the TXT record is missing.
	FailValidation atomic.Bool
	// CertValidity sets the lifetime of issued certificates (default 90 days).
	CertValidity time.Duration

	caKey  *ecdsa.PrivateKey
	caCert *x509.Certificate
	caDER  []byte

	mu     sync.Mutex
	nextID int
	orders map[string]*order
	authzs map[string]*authz
	nonce  int
}

type order struct {
	id, domain, status, authzID, certPEM string
}

type authz struct {
	id, domain, status, orderID string
}

// New starts a fake ACME server; it is closed when the test ends via Close.
func New() *Server {
	s := &Server{orders: map[string]*order{}, authzs: map[string]*authz{}, CertValidity: 90 * 24 * time.Hour}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "acmetest CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	s.caKey, s.caDER = key, der
	s.caCert, _ = x509.ParseCertificate(der)
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// DirectoryURL is the ACME directory to configure clients with.
func (s *Server) DirectoryURL() string { return s.URL + "/directory" }

// CAPool returns a pool trusting the fake CA.
func (s *Server) CAPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.caCert)
	return p
}

func (s *Server) newID(prefix string) string {
	s.nextID++
	return fmt.Sprintf("%s%d", prefix, s.nextID)
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonce++
	w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", s.nonce))

	path := r.URL.Path
	switch {
	case path == "/directory":
		writeJSON(w, http.StatusOK, map[string]string{
			"newNonce":   s.URL + "/new-nonce",
			"newAccount": s.URL + "/new-account",
			"newOrder":   s.URL + "/new-order",
			"revokeCert": s.URL + "/revoke-cert",
			"keyChange":  s.URL + "/key-change",
		})
	case path == "/new-nonce":
		w.WriteHeader(http.StatusOK)
	case path == "/new-account":
		// An account lookup (onlyReturnExisting) answers 200; creation 201.
		var req struct {
			OnlyReturnExisting bool `json:"onlyReturnExisting"`
		}
		_ = decodePayload(r, &req)
		w.Header().Set("Location", s.URL+"/account/1")
		status := http.StatusCreated
		if req.OnlyReturnExisting {
			status = http.StatusOK
		}
		writeJSON(w, status, map[string]interface{}{"status": "valid"})
	case path == "/new-order":
		var req struct {
			Identifiers []struct{ Value string } `json:"identifiers"`
		}
		if err := decodePayload(r, &req); err != nil || len(req.Identifiers) == 0 || req.Identifiers[0].Value == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"type": "urn:ietf:params:acme:error:rejectedIdentifier", "detail": "invalid identifier"})
			return
		}
		o := &order{id: s.newID("o"), domain: req.Identifiers[0].Value, status: "pending"}
		a := &authz{id: s.newID("a"), domain: o.domain, status: "pending", orderID: o.id}
		o.authzID = a.id
		s.orders[o.id], s.authzs[a.id] = o, a
		w.Header().Set("Location", s.URL+"/order/"+o.id)
		writeJSON(w, http.StatusCreated, s.orderJSON(o))
	case strings.HasPrefix(path, "/order/"):
		o, ok := s.orders[strings.TrimPrefix(path, "/order/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Location", s.URL+"/order/"+o.id)
		writeJSON(w, http.StatusOK, s.orderJSON(o))
	case strings.HasPrefix(path, "/authz/"):
		a, ok := s.authzs[strings.TrimPrefix(path, "/authz/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, s.authzJSON(a))
	case strings.HasPrefix(path, "/challenge/"):
		a, ok := s.authzs[strings.TrimPrefix(path, "/challenge/")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if s.FailValidation.Load() {
			a.status = "invalid"
			s.orders[a.orderID].status = "invalid"
		} else {
			a.status = "valid"
			s.orders[a.orderID].status = "ready"
		}
		writeJSON(w, http.StatusOK, s.challengeJSON(a))
	case strings.HasPrefix(path, "/finalize/"):
		o, ok := s.orders[strings.TrimPrefix(path, "/finalize/")]
		if !ok || o.status != "ready" {
			writeJSON(w, http.StatusForbidden, map[string]string{"type": "urn:ietf:params:acme:error:orderNotReady", "detail": "order not ready"})
			return
		}
		var req struct {
			CSR string `json:"csr"`
		}
		if err := decodePayload(r, &req); err != nil {
			http.Error(w, "bad finalize", http.StatusBadRequest)
			return
		}
		certPEM, err := s.issue(req.CSR)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"type": "urn:ietf:params:acme:error:badCSR", "detail": err.Error()})
			return
		}
		o.status, o.certPEM = "valid", certPEM
		w.Header().Set("Location", s.URL+"/order/"+o.id)
		writeJSON(w, http.StatusOK, s.orderJSON(o))
	case strings.HasPrefix(path, "/cert/"):
		o, ok := s.orders[strings.TrimPrefix(path, "/cert/")]
		if !ok || o.certPEM == "" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/pem-certificate-chain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(o.certPEM))
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) orderJSON(o *order) map[string]interface{} {
	m := map[string]interface{}{
		"status":         o.status,
		"identifiers":    []map[string]string{{"type": "dns", "value": o.domain}},
		"authorizations": []string{s.URL + "/authz/" + o.authzID},
		"finalize":       s.URL + "/finalize/" + o.id,
	}
	if o.status == "valid" {
		m["certificate"] = s.URL + "/cert/" + o.id
	}
	return m
}

func (s *Server) challengeJSON(a *authz) map[string]interface{} {
	return map[string]interface{}{
		"type":   "dns-01",
		"url":    s.URL + "/challenge/" + a.id,
		"token":  "token-" + a.id,
		"status": a.status,
	}
}

func (s *Server) authzJSON(a *authz) map[string]interface{} {
	return map[string]interface{}{
		"status":     a.status,
		"identifier": map[string]string{"type": "dns", "value": a.domain},
		"challenges": []interface{}{s.challengeJSON(a)},
	}
}

// issue signs the CSR (base64url DER) and returns leaf + CA as PEM.
func (s *Server) issue(csrB64 string) (string, error) {
	der, err := base64.RawURLEncoding.DecodeString(csrB64)
	if err != nil {
		return "", err
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: firstOr(csr.DNSNames, "")},
		DNSNames:     csr.DNSNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(s.CertValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf, err := x509.CreateCertificate(rand.Reader, tmpl, s.caCert, csr.PublicKey, s.caKey)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})) +
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.caDER})), nil
}

func firstOr(v []string, def string) string {
	if len(v) > 0 {
		return v[0]
	}
	return def
}

// decodePayload extracts the JSON payload from a flattened JWS body.
func decodePayload(r *http.Request, v interface{}) error {
	var jws struct {
		Payload string `json:"payload"`
	}
	if err := json.NewDecoder(r.Body).Decode(&jws); err != nil {
		return err
	}
	raw, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, v)
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
