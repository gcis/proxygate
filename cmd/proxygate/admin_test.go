package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/auth"
)

// pipedStdin returns a non-terminal stdin carrying input.
func pipedStdin(t *testing.T, input string) *os.File {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.WriteString(input); err != nil {
		t.Fatal(err)
	}
	w.Close()
	t.Cleanup(func() { r.Close() })
	return r
}

func adminCmd(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errOut syncBuffer
	handled, code := runAdminCommand(args, pipedStdin(t, stdin), &out, &errOut)
	if !handled {
		t.Fatalf("%v not handled", args)
	}
	return code, out.String(), errOut.String()
}

func TestRunAdminCommand_NotHandled(t *testing.T) {
	for _, args := range [][]string{nil, {"-config", "x"}, {"serve"}} {
		if handled, _ := runAdminCommand(args, os.Stdin, &syncBuffer{}, &syncBuffer{}); handled {
			t.Errorf("%v should fall through to the server", args)
		}
	}
}

func TestPasswd(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "proxygate.json")
	_ = os.WriteFile(cfg, []byte("{}"), 0640)
	store := auth.NewStore(dir)

	code, out, _ := adminCmd(t, "first passphrase\n", "passwd", "--config", cfg)
	if code != 0 || !strings.Contains(out, "signed out") || !store.CheckPassword("first passphrase") {
		t.Fatalf("piped password: %d %q", code, out)
	}

	code, out, errOut := adminCmd(t, "", "passwd", "--config", cfg, "--generate", "--policy", "strong")
	generated := strings.TrimSpace(out)
	if code != 0 || len(generated) != 24 || !store.CheckPassword(generated) || !strings.Contains(errOut, "above") {
		t.Fatalf("--generate: %d %q %q", code, out, errOut)
	}
	if f, _ := store.Load(); !f.StrongPolicy {
		t.Error("--policy strong not saved")
	}

	if code, _, errOut := adminCmd(t, "short1234\n", "passwd", "--config", cfg); code != 1 || !strings.Contains(errOut, "12 characters") {
		t.Errorf("strong policy must reject short passwords: %d %q", code, errOut)
	}
	if code, _, _ := adminCmd(t, "short1234\n", "passwd", "--config", cfg, "--policy", "basic"); code != 0 {
		t.Errorf("--policy basic should relax the rules: %d", code)
	}
	if code, _, _ := adminCmd(t, "", "passwd", "--config", cfg); code != 1 {
		t.Errorf("empty stdin: want 1, got %d", code)
	}
	if code, _, _ := adminCmd(t, "x\n", "passwd", "--config", cfg, "--policy", "weird"); code != 2 {
		t.Errorf("bad policy: want 2, got %d", code)
	}
	if code, _, _ := adminCmd(t, "x\n", "passwd", "--bogus"); code != 2 {
		t.Errorf("bad flag: want 2, got %d", code)
	}
	if code, _, errOut := adminCmd(t, "x\n", "passwd", "--config", filepath.Join(dir, "missing", "p.json")); code != 1 || !strings.Contains(errOut, "config directory") {
		t.Errorf("missing dir: %d %q", code, errOut)
	}
}

func TestToken(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "proxygate.json")
	_ = os.WriteFile(cfg, []byte("{}"), 0640)
	store := auth.NewStore(dir)

	if code, out, _ := adminCmd(t, "", "token", "list", "--config", cfg); code != 0 || !strings.Contains(out, "No API tokens") {
		t.Errorf("empty list: %d %q", code, out)
	}
	code, out, errOut := adminCmd(t, "", "token", "create", "ci", "--config", cfg)
	secret := strings.TrimSpace(out)
	if code != 0 || !store.CheckToken(secret) || !strings.Contains(errOut, "shown only once") {
		t.Fatalf("create: %d %q %q", code, out, errOut)
	}
	// Name after the flags works too.
	if code, _, _ := adminCmd(t, "", "token", "create", "--config", cfg, "backup"); code != 0 {
		t.Errorf("create with trailing name: %d", code)
	}
	if code, out, _ := adminCmd(t, "", "token", "list", "--config", cfg); code != 0 || !strings.Contains(out, "ci\t") || !strings.Contains(out, "backup\t") || strings.Contains(out, secret) {
		t.Errorf("list must show names and never secrets: %q", out)
	}
	if code, _, _ := adminCmd(t, "", "token", "create", "ci", "--config", cfg); code != 1 {
		t.Errorf("duplicate: want 1, got %d", code)
	}
	if code, out, _ := adminCmd(t, "", "token", "revoke", "ci", "--config", cfg); code != 0 || !strings.Contains(out, "revoked") || store.CheckToken(secret) {
		t.Errorf("revoke: %d %q", code, out)
	}
	if code, _, _ := adminCmd(t, "", "token", "revoke", "ci", "--config", cfg); code != 1 {
		t.Errorf("revoke missing: want 1, got %d", code)
	}

	for _, args := range [][]string{{"token"}, {"token", "create", "--config", cfg}, {"token", "revoke", "--config", cfg}, {"token", "rename", "--config", cfg}, {"token", "list", "--bogus"}} {
		if code, _, _ := adminCmd(t, "", args...); code != 2 {
			t.Errorf("%v: want usage error 2, got %d", args, code)
		}
	}
	if code, _, _ := adminCmd(t, "", "token", "list", "--config", filepath.Join(dir, "nope", "p.json")); code != 1 {
		t.Errorf("missing dir: want 1, got %d", code)
	}
	_ = os.WriteFile(filepath.Join(dir, auth.AuthFileName), []byte("{"), 0600)
	if code, _, _ := adminCmd(t, "", "token", "list", "--config", cfg); code != 1 {
		t.Errorf("corrupt auth file: want 1, got %d", code)
	}
	if code, _, _ := adminCmd(t, "", "token", "create", "new", "--config", cfg); code != 1 {
		t.Errorf("create on corrupt auth file: want 1, got %d", code)
	}
	if code, _, _ := adminCmd(t, "", "token", "revoke", "x", "--config", cfg); code != 1 {
		t.Errorf("revoke on corrupt auth file: want 1, got %d", code)
	}
	if code, _, _ := adminCmd(t, "pass phrase here\n", "passwd", "--config", cfg); code != 1 {
		t.Errorf("passwd on corrupt auth file: want 1, got %d", code)
	}
}

func TestMatchOwnership(t *testing.T) {
	dir := t.TempDir()
	ref, file := filepath.Join(dir, "ref"), filepath.Join(dir, "file")
	_ = os.WriteFile(ref, nil, 0600)
	_ = os.WriteFile(file, nil, 0600)

	// Not root: nothing happens.
	matchOwnership(ref, file)

	// Pretend to be root: chowning to our own uid/gid is allowed for anyone.
	orig := geteuid
	geteuid = func() int { return 0 }
	defer func() { geteuid = orig }()
	matchOwnership(ref, file)
	matchOwnership(filepath.Join(dir, "missing"), file) // unreadable reference is ignored
}
