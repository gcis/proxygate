package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	selfSignedCertName = "admin-tls.crt"
	selfSignedKeyName  = "admin-tls.key"
	selfSignedValidity = 397 * 24 * time.Hour // the longest validity browsers accept
	selfSignedRenewal  = 30 * 24 * time.Hour
)

// adminTLSConfig builds the TLS config for the admin listener from the
// security settings, generating a self-signed certificate when none is
// configured. It returns the certificate's SHA-256 fingerprint for the log.
func (s *Server) adminTLSConfig() (*tls.Config, string, error) {
	certFile := s.security.AdminTLS.CertFile
	keyFile := s.security.AdminTLS.KeyFile
	if certFile == "" || keyFile == "" {
		certFile = filepath.Join(s.dataDir, selfSignedCertName)
		keyFile = filepath.Join(s.dataDir, selfSignedKeyName)
		if err := ensureSelfSigned(certFile, keyFile, s.configMgr.Get().Server.AdminHost); err != nil {
			return nil, "", fmt.Errorf("self-signed admin certificate: %w", err)
		}
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, "", fmt.Errorf("loading admin certificate: %w", err)
	}
	sum := sha256.Sum256(cert.Certificate[0])
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}, colonHex(sum[:]), nil
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	parts := make([]string, 0, len(h)/2)
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// ensureSelfSigned keeps a valid self-signed certificate at certFile. It is
// regenerated when missing, unreadable or within 30 days of expiry.
func ensureSelfSigned(certFile, keyFile, adminHost string) error {
	if data, err := os.ReadFile(certFile); err == nil {
		if block, _ := pem.Decode(data); block != nil {
			if c, err := x509.ParseCertificate(block.Bytes); err == nil && time.Until(c.NotAfter) > selfSignedRenewal {
				if _, err := os.Stat(keyFile); err == nil {
					return nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	dnsNames, ips := selfSignedNames(adminHost)
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ProxyGate admin", Organization: []string{"ProxyGate (self-signed)"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(selfSignedValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0750); err != nil {
		return err
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		return err
	}
	return os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644)
}

// selfSignedNames lists the names a browser may use to reach the admin UI:
// localhost, the hostname, the configured admin host and every address on
// the machine's interfaces (LAN, Tailscale, ...).
func selfSignedNames(adminHost string) ([]string, []net.IP) {
	dns := []string{"localhost"}
	if h, err := os.Hostname(); err == nil && h != "" && h != "localhost" {
		dns = append(dns, h)
	}
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	seen := map[string]bool{"127.0.0.1": true, "::1": true}
	if ip := net.ParseIP(adminHost); ip != nil && !ip.IsUnspecified() && !seen[ip.String()] {
		ips = append(ips, ip)
		seen[ip.String()] = true
	} else if adminHost != "" && ip == nil && adminHost != "localhost" {
		dns = append(dns, adminHost)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.IsLinkLocalUnicast() || seen[ipNet.IP.String()] {
				continue
			}
			ips = append(ips, ipNet.IP)
			seen[ipNet.IP.String()] = true
		}
	}
	return dns, ips
}
