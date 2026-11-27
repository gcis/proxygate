package api

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	// A DNS label: alphanumerics and inner hyphens, 1-63 chars.
	labelRe = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	// DNS record names relative to the zone ("@", "www", "_acme-challenge.app", "*").
	recordNameRe = regexp.MustCompile(`^[a-zA-Z0-9._@*-]+$`)
	emailRe      = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

var dnsRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "NS": true, "SRV": true, "CAA": true,
}

// allowedGoDaddyBaseURLs keeps API credentials from being sent to arbitrary
// hosts (an SSRF / credential-exfiltration vector via PUT /api/godaddy/config).
var allowedGoDaddyBaseURLs = map[string]bool{
	"https://api.godaddy.com":     true,
	"https://api.ote-godaddy.com": true,
}

const (
	acmeProductionDirectory = "https://acme-v02.api.letsencrypt.org/directory"
	acmeStagingDirectory    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

// normalizeDomain lowercases and trims a route domain and checks it is a
// hostname (optionally a "*." wildcard). Single-label names such as "nas"
// are allowed for LAN use.
func normalizeDomain(raw string) (string, error) {
	d := strings.ToLower(strings.TrimSpace(raw))
	d = strings.TrimSuffix(d, ".")
	if d == "" {
		return "", fmt.Errorf("domain is required")
	}
	if len(d) > 253 {
		return "", fmt.Errorf("domain is too long")
	}
	host := strings.TrimPrefix(d, "*.")
	for _, label := range strings.Split(host, ".") {
		if !labelRe.MatchString(label) {
			return "", fmt.Errorf("invalid domain %q (expected e.g. app.example.com)", raw)
		}
	}
	return d, nil
}

// normalizeTargetHost accepts a hostname, IPv4 or IPv6 address (brackets
// optional) and returns it without brackets.
func normalizeTargetHost(raw string) (string, error) {
	h := strings.TrimSpace(raw)
	if h == "" {
		return "", fmt.Errorf("target_host is required")
	}
	unbracketed := strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	if ip := net.ParseIP(unbracketed); ip != nil {
		return unbracketed, nil
	}
	if strings.ContainsAny(h, ":/\\ ") {
		return "", fmt.Errorf("invalid target_host %q (use a hostname or IP, without scheme or port)", raw)
	}
	if len(h) > 253 {
		return "", fmt.Errorf("target_host is too long")
	}
	for _, label := range strings.Split(strings.ToLower(h), ".") {
		if !labelRe.MatchString(label) {
			return "", fmt.Errorf("invalid target_host %q", raw)
		}
	}
	return h, nil
}

func validPort(p int) bool { return p >= 1 && p <= 65535 }

func normalizePathPrefix(raw string) (string, error) {
	p := strings.TrimSpace(raw)
	if p == "" {
		return "", nil
	}
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf(`path_prefix must start with "/"`)
	}
	if strings.Contains(p, "..") || strings.ContainsAny(p, " \t\r\n?#") {
		return "", fmt.Errorf(`path_prefix cannot contain "..", whitespace, "?" or "#"`)
	}
	if len(p) > 256 {
		return "", fmt.Errorf("path_prefix is too long")
	}
	return p, nil
}

// parseNetwork accepts CIDR notation or a bare IP, mirroring NetworkWhitelist.
func parseNetwork(s string) (*net.IPNet, error) {
	if _, n, err := net.ParseCIDR(s); err == nil {
		return n, nil
	}
	if ip := net.ParseIP(s); ip != nil {
		bits := 128
		if ip.To4() != nil {
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	return nil, fmt.Errorf("invalid network %q (use CIDR like 192.168.1.0/24 or a single IP)", s)
}

func validEmail(s string) bool { return emailRe.MatchString(s) }

func validRecordName(s string) bool {
	return s != "" && len(s) <= 255 && recordNameRe.MatchString(s)
}

func validRecordType(s string) bool { return dnsRecordTypes[strings.ToUpper(s)] }

func normalizeGoDaddyBaseURL(raw string) (string, error) {
	u := strings.TrimRight(strings.TrimSpace(raw), "/")
	if u == "" {
		return "https://api.godaddy.com", nil
	}
	if !allowedGoDaddyBaseURLs[u] {
		return "", fmt.Errorf("base_url must be https://api.godaddy.com or https://api.ote-godaddy.com")
	}
	return u, nil
}

// normalizeACMEDirectory picks the Let's Encrypt directory matching
// useStaging when none is given, and otherwise requires an https URL so a
// custom CA (e.g. a private step-ca) still works.
func normalizeACMEDirectory(raw string, useStaging bool) (string, error) {
	d := strings.TrimSpace(raw)
	if d == "" {
		if useStaging {
			return acmeStagingDirectory, nil
		}
		return acmeProductionDirectory, nil
	}
	u, err := url.Parse(d)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("directory must be an https:// ACME directory URL")
	}
	return d, nil
}
