package api

import "testing"

func TestNormalizeDomain(t *testing.T) {
	ok := map[string]string{
		"App.Example.com":  "app.example.com",
		" a.b.c.io ":       "a.b.c.io",
		"*.example.com":    "*.example.com",
		"nas":              "nas",
		"example.com.":     "example.com",
		"xn--bcher-kva.de": "xn--bcher-kva.de",
	}
	for in, want := range ok {
		got, err := normalizeDomain(in)
		if err != nil || got != want {
			t.Errorf("normalizeDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://a.com", "a.com/x", "a b.com", "-a.com", "a..com", "a.com:80", "*.*.a.com"} {
		if _, err := normalizeDomain(bad); err == nil {
			t.Errorf("normalizeDomain(%q) should fail", bad)
		}
	}
}

func TestNormalizeTargetHost(t *testing.T) {
	ok := map[string]string{
		"127.0.0.1":     "127.0.0.1",
		"[::1]":         "::1",
		"fd00::10":      "fd00::10",
		"backend.local": "backend.local",
		"localhost":     "localhost",
	}
	for in, want := range ok {
		got, err := normalizeTargetHost(in)
		if err != nil || got != want {
			t.Errorf("normalizeTargetHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "http://x", "x:8080", "a b", "x/y"} {
		if _, err := normalizeTargetHost(bad); err == nil {
			t.Errorf("normalizeTargetHost(%q) should fail", bad)
		}
	}
}

func TestNormalizePathPrefix(t *testing.T) {
	for _, good := range []string{"", "/", "/api", "/api/v2"} {
		if _, err := normalizePathPrefix(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"api", "/../etc", "/a b", "/a?x"} {
		if _, err := normalizePathPrefix(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestParseNetwork(t *testing.T) {
	for _, good := range []string{"10.0.0.0/8", "::1/128", "203.0.113.5", "fe80::1"} {
		if _, err := parseNetwork(good); err != nil {
			t.Errorf("%q: %v", good, err)
		}
	}
	for _, bad := range []string{"", "10.0.0.0/99", "not-an-ip"} {
		if _, err := parseNetwork(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestNormalizeGoDaddyBaseURL(t *testing.T) {
	if u, err := normalizeGoDaddyBaseURL(""); err != nil || u != "https://api.godaddy.com" {
		t.Errorf("empty: %q %v", u, err)
	}
	if u, err := normalizeGoDaddyBaseURL("https://api.ote-godaddy.com/"); err != nil || u != "https://api.ote-godaddy.com" {
		t.Errorf("ote: %q %v", u, err)
	}
	if _, err := normalizeGoDaddyBaseURL("https://evil.example.com"); err == nil {
		t.Error("arbitrary host must be rejected")
	}
}

func TestNormalizeACMEDirectory(t *testing.T) {
	if d, _ := normalizeACMEDirectory("", true); d != acmeStagingDirectory {
		t.Errorf("staging default: %q", d)
	}
	if d, _ := normalizeACMEDirectory("", false); d != acmeProductionDirectory {
		t.Errorf("production default: %q", d)
	}
	if _, err := normalizeACMEDirectory("https://ca.internal/acme/directory", false); err != nil {
		t.Errorf("custom https CA should be allowed: %v", err)
	}
	if _, err := normalizeACMEDirectory("http://ca.internal/dir", false); err == nil {
		t.Error("plain http directory must be rejected")
	}
}

func TestRecordValidators(t *testing.T) {
	if !validRecordType("txt") || validRecordType("PTR") {
		t.Error("record type check wrong")
	}
	if !validRecordName("@") || !validRecordName("_acme-challenge.app") || validRecordName("a b") || validRecordName("") {
		t.Error("record name check wrong")
	}
	if !validEmail("a@b.co") || validEmail("nope") {
		t.Error("email check wrong")
	}
}
