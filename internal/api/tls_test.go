package api

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestEnsureSelfSigned(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "c.crt"), filepath.Join(dir, "c.key")

	if err := ensureSelfSigned(certFile, keyFile, "admin.lan"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(certFile)
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hasDNS := map[string]bool{}
	for _, n := range cert.DNSNames {
		hasDNS[n] = true
	}
	if !hasDNS["localhost"] || !hasDNS["admin.lan"] {
		t.Errorf("DNS names: %v", cert.DNSNames)
	}
	hasLoopback := false
	for _, ip := range cert.IPAddresses {
		if ip.IsLoopback() {
			hasLoopback = true
		}
	}
	if !hasLoopback {
		t.Errorf("IPs: %v", cert.IPAddresses)
	}
	if info, _ := os.Stat(keyFile); info.Mode().Perm() != 0600 {
		t.Errorf("key mode: %v", info.Mode().Perm())
	}

	// A valid certificate is reused, not regenerated on every start.
	if err := ensureSelfSigned(certFile, keyFile, "admin.lan"); err != nil {
		t.Fatal(err)
	}
	again, _ := os.ReadFile(certFile)
	if string(again) != string(data) {
		t.Error("certificate regenerated although still valid")
	}
}
