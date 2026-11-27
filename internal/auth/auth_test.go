package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=47104,t=1,p=1$") {
		t.Errorf("unexpected hash format: %s", h)
	}
	if !VerifyPassword("correct horse battery", h) {
		t.Error("correct password rejected")
	}
	if VerifyPassword("correct horse batterY", h) || VerifyPassword("", h) || VerifyPassword("x", "garbage") {
		t.Error("wrong password or malformed hash accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Error("hashes must be salted")
	}
}

func TestValidatePassword(t *testing.T) {
	cases := []struct {
		pw     string
		strong bool
		ok     bool
	}{
		{"short", false, false},
		{"eightchr", false, true},
		{"password", false, true}, // baseline only checks length
		{"elevenchars", true, false},
		{"Password123!", true, true},
		{"password1234", true, false},   // common
		{"myproxygate-pw", true, false}, // contains product name
		{"aaaaaaaaaaaaaa", true, false}, // single repeated character
		{"ééééééééééééé", true, false},  // repeated multibyte character
		{"a calm river at dawn", true, true},
		{strings.Repeat("x", 257), false, false},
	}
	for _, c := range cases {
		err := ValidatePassword(c.pw, c.strong)
		if (err == nil) != c.ok {
			t.Errorf("ValidatePassword(%q, strong=%v): ok=%v, err=%v", c.pw, c.strong, c.ok, err)
		}
	}
}

func TestRandomPassword(t *testing.T) {
	p, err := RandomPassword()
	if err != nil || len(p) != 24 {
		t.Fatalf("got %q, %v", p, err)
	}
	if err := ValidatePassword(p, true); err != nil {
		t.Errorf("generated password must satisfy strong policy: %v", err)
	}
}

func readCode(t *testing.T, s *Store) string {
	t.Helper()
	data, err := os.ReadFile(s.SetupCodePath())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(data))
}

func TestSetupFlow(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	if req, _ := s.SetupRequired(); !req {
		t.Fatal("fresh store must require setup")
	}
	path, err := s.EnsureSetupCode()
	if err != nil || path == "" {
		t.Fatalf("EnsureSetupCode: %q %v", path, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Errorf("setup code mode: %v", info.Mode().Perm())
	}
	code := readCode(t, s)
	if again, _ := s.EnsureSetupCode(); again != path || readCode(t, s) != code {
		t.Error("EnsureSetupCode must keep an existing code")
	}

	if err := s.CompleteSetup("WRONG-CODE", "long enough pw", false); err != ErrBadSetupCode {
		t.Errorf("wrong code: got %v", err)
	}
	// Codes are accepted case-insensitively and without dashes.
	if err := s.CompleteSetup(strings.ToLower(strings.ReplaceAll(code, "-", "")), "a strong passphrase", true); err != nil {
		t.Fatalf("CompleteSetup: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("setup code file must be deleted after use")
	}
	if err := s.CompleteSetup(code, "another passphrase", false); err != ErrSetupDone {
		t.Errorf("second setup: got %v", err)
	}
	if !s.CheckPassword("a strong passphrase") || s.CheckPassword("nope") {
		t.Error("password check wrong after setup")
	}
	f, _ := s.Load()
	if !f.StrongPolicy || f.SessionEpoch != 1 {
		t.Errorf("policy/epoch: %+v", f)
	}
	authInfo, _ := os.Stat(filepath.Join(dir, AuthFileName))
	if authInfo.Mode().Perm() != 0600 {
		t.Errorf("auth file mode: %v", authInfo.Mode().Perm())
	}
	raw, _ := os.ReadFile(filepath.Join(dir, AuthFileName))
	if strings.Contains(string(raw), "a strong passphrase") {
		t.Fatal("plaintext password stored")
	}
}

func TestStrongPolicyAppliesToLaterChanges(t *testing.T) {
	s := NewStore(t.TempDir())
	strong := true
	if err := s.SetPassword("a strong passphrase", &strong); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPassword("short123", nil); err == nil {
		t.Error("strong policy must apply to later changes")
	}
	weak := false
	if err := s.SetPassword("short123", &weak); err != nil {
		t.Errorf("explicitly relaxing the policy (CLI) should work: %v", err)
	}
}

func TestPasswordChangeBumpsEpoch(t *testing.T) {
	s := NewStore(t.TempDir())
	_ = s.SetPassword("first password", nil)
	f1, _ := s.Load()
	_ = s.SetPassword("second password", nil)
	f2, _ := s.Load()
	if f2.SessionEpoch != f1.SessionEpoch+1 {
		t.Errorf("epoch: %d -> %d", f1.SessionEpoch, f2.SessionEpoch)
	}
}

func TestStoreSeesExternalReset(t *testing.T) {
	dir := t.TempDir()
	server := NewStore(dir)
	_ = server.SetPassword("server password", nil)
	if !server.CheckPassword("server password") {
		t.Fatal("setup failed")
	}
	// Simulate `proxygate passwd` in another process with its own Store.
	time.Sleep(10 * time.Millisecond)
	cli := NewStore(dir)
	if err := cli.SetPassword("reset password", nil); err != nil {
		t.Fatal(err)
	}
	if server.CheckPassword("server password") || !server.CheckPassword("reset password") {
		t.Error("server store did not pick up the external reset")
	}
}

func TestTokens(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	secret, err := s.CreateToken("backup")
	if err != nil || !strings.HasPrefix(secret, "pgt_") {
		t.Fatalf("CreateToken: %q %v", secret, err)
	}
	if _, err := s.CreateToken("backup"); err != ErrTokenExists {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := s.CreateToken("bad name"); err != ErrInvalidTokenName {
		t.Errorf("bad name: %v", err)
	}
	if !s.CheckToken(secret) || s.CheckToken(secret+"x") || s.CheckToken("") {
		t.Error("token check wrong")
	}
	raw, _ := os.ReadFile(filepath.Join(dir, AuthFileName))
	if strings.Contains(string(raw), secret) {
		t.Fatal("token secret stored in plaintext")
	}
	var f File
	_ = json.Unmarshal(raw, &f)
	if len(f.Tokens) != 1 || f.Tokens[0].Name != "backup" {
		t.Errorf("stored tokens: %+v", f.Tokens)
	}
	if err := s.RevokeToken("backup"); err != nil {
		t.Fatal(err)
	}
	if s.CheckToken(secret) {
		t.Error("revoked token still accepted")
	}
	if err := s.RevokeToken("backup"); err != ErrTokenNotFound {
		t.Errorf("revoke missing: %v", err)
	}
}

func TestSessions(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := NewSessions(time.Hour, 3*time.Hour)
	s.now = func() time.Time { return now }

	id, err := s.Create(1)
	if err != nil || len(id) < 40 {
		t.Fatalf("Create: %q %v", id, err)
	}
	if !s.Valid(id, 1) {
		t.Fatal("fresh session invalid")
	}
	if s.Valid(id, 2) {
		t.Error("session must die when the password epoch changes")
	}

	id, _ = s.Create(1)
	now = now.Add(59 * time.Minute)
	if !s.Valid(id, 1) {
		t.Error("activity within idle window must keep session")
	}
	now = now.Add(61 * time.Minute)
	if s.Valid(id, 1) {
		t.Error("idle timeout not enforced")
	}

	id, _ = s.Create(1)
	for i := 0; i < 4; i++ {
		now = now.Add(50 * time.Minute)
		s.Valid(id, 1)
	}
	if s.Valid(id, 1) {
		t.Error("absolute lifetime not enforced")
	}

	id, _ = s.Create(1)
	s.Delete(id)
	if s.Valid(id, 1) {
		t.Error("deleted session still valid")
	}
}

func TestLoginLimiter(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	l := NewLoginLimiter(3, 15*time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < 3; i++ {
		if blocked, _ := l.Blocked("1.2.3.4"); blocked {
			t.Fatalf("blocked too early at %d", i)
		}
		l.Fail("1.2.3.4")
	}
	if blocked, wait := l.Blocked("1.2.3.4"); !blocked || wait <= 0 {
		t.Error("must block after max failures")
	}
	if blocked, _ := l.Blocked("5.6.7.8"); blocked {
		t.Error("other addresses must not be affected")
	}
	now = now.Add(16 * time.Minute)
	if blocked, _ := l.Blocked("1.2.3.4"); blocked {
		t.Error("block must expire with the window")
	}
	l.Fail("9.9.9.9")
	l.Succeed("9.9.9.9")
	if blocked, _ := l.Blocked("9.9.9.9"); blocked {
		t.Error("success must clear failures")
	}
}
