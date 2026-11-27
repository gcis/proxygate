package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStore_CorruptFileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	_ = os.WriteFile(filepath.Join(dir, AuthFileName), []byte("{"), 0600)

	if _, err := s.Load(); err == nil {
		t.Error("corrupt file must error")
	}
	if s.CheckPassword("anything") {
		t.Error("corrupt file must never authenticate a password")
	}
	if s.CheckToken("pgt_anything") {
		t.Error("corrupt file must never authenticate a token")
	}
	if _, err := s.CreateToken("x"); err == nil {
		t.Error("CreateToken on corrupt file must fail")
	}
	if err := s.RevokeToken("x"); err == nil {
		t.Error("RevokeToken on corrupt file must fail")
	}
	if _, err := s.EnsureSetupCode(); err == nil {
		t.Error("EnsureSetupCode on corrupt file must fail")
	}
	if err := s.CompleteSetup("x", "long enough pw", false); err == nil {
		t.Error("CompleteSetup on corrupt file must fail")
	}
	if err := s.SetPassword("long enough pw", nil); err == nil {
		t.Error("SetPassword on corrupt file must fail")
	}
	if _, err := s.Tokens(); err == nil {
		t.Error("Tokens on corrupt file must fail")
	}
}

func TestStore_SetupEdges(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if s.CheckPassword("x") {
		t.Error("no password set must not authenticate")
	}
	// No setup code file yet.
	if err := s.CompleteSetup("anything", "long enough pw", false); err != ErrBadSetupCode {
		t.Errorf("missing code file: %v", err)
	}
	// Once a password exists no setup code is created.
	_ = s.SetPassword("long enough pw", nil)
	if path, err := s.EnsureSetupCode(); err != nil || path != "" {
		t.Errorf("EnsureSetupCode after setup: %q %v", path, err)
	}
	if toks, err := s.Tokens(); err != nil || len(toks) != 0 {
		t.Errorf("Tokens: %v %v", toks, err)
	}
	_, _ = s.CreateToken("one")
	if toks, _ := s.Tokens(); len(toks) != 1 || toks[0].Name != "one" || toks[0].Hash == "" {
		t.Errorf("Tokens after create: %+v", toks)
	}
}

func TestStore_UnwritableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	dir := t.TempDir()
	s := NewStore(dir)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0700) //nolint:errcheck
	if err := s.SetPassword("long enough pw", nil); err == nil {
		t.Error("write into read-only dir must fail")
	}
	if _, err := s.EnsureSetupCode(); err == nil {
		t.Error("setup code into read-only dir must fail")
	}

	// Data dir path under a regular file cannot be created at all.
	file := filepath.Join(t.TempDir(), "f")
	_ = os.WriteFile(file, nil, 0600)
	bad := NewStore(filepath.Join(file, "sub"))
	if err := bad.SetPassword("long enough pw", nil); err == nil {
		t.Error("data dir under a file must fail")
	}
	if _, err := bad.EnsureSetupCode(); err == nil {
		t.Error("setup code under a file must fail")
	}
}

func TestVerifyPassword_MalformedHashes(t *testing.T) {
	good, _ := HashPassword("pw")
	parts := strings.Split(good, "$")
	bad := []string{
		"",
		"$bcrypt$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$" + strings.Join(parts[3:], "$"),
		"$argon2id$v=19$m=x$" + strings.Join(parts[4:], "$"),
		"$argon2id$v=19$" + parts[3] + "$!!!$" + parts[5],
		"$argon2id$v=19$" + parts[3] + "$" + parts[4] + "$!!!",
		"$argon2id$v=19$" + parts[3] + "$" + parts[4] + "$",
		"$argon2id$vv$" + strings.Join(parts[3:], "$"),
	}
	for _, h := range bad {
		if VerifyPassword("pw", h) {
			t.Errorf("malformed hash accepted: %q", h)
		}
	}
}

func TestSessions_PruneDropsExpired(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSessions(time.Minute, time.Hour)
	s.now = func() time.Time { return now }
	old, _ := s.Create(1)
	now = now.Add(2 * time.Minute)
	_, _ = s.Create(1) // prunes the idle one
	s.mu.Lock()
	_, stillThere := s.m[old]
	s.mu.Unlock()
	if stillThere {
		t.Error("expired session not pruned")
	}
	if s.Valid("", 1) || s.Valid("unknown", 1) {
		t.Error("empty or unknown session ID accepted")
	}
}
