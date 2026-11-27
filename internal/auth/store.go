package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	// AuthFileName holds the password hash, policy and API token hashes.
	AuthFileName = "admin-auth.json"
	// SetupCodeFileName holds the one-time code that unlocks first setup.
	SetupCodeFileName = "setup-code"

	tokenPrefix = "pgt_"
)

var (
	ErrSetupDone        = errors.New("an admin password is already set")
	ErrBadSetupCode     = errors.New("the setup code is not correct")
	ErrTokenExists      = errors.New("a token with that name already exists")
	ErrTokenNotFound    = errors.New("no token with that name")
	ErrInvalidTokenName = errors.New("token names may only contain letters, digits, '.', '_' and '-' (max 64)")
)

var tokenNameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// File is the on-disk content of admin-auth.json.
type File struct {
	PasswordHash      string `json:"password_hash,omitempty"`
	StrongPolicy      bool   `json:"strong_password_policy"`
	PasswordChangedAt string `json:"password_changed_at,omitempty"`
	// SessionEpoch changes whenever the password changes; sessions created
	// under an older epoch are rejected, which signs everyone out.
	SessionEpoch int     `json:"session_epoch"`
	Tokens       []Token `json:"tokens,omitempty"`
}

// Token is an API token; only the SHA-256 of the secret is stored.
type Token struct {
	Name      string `json:"name"`
	Hash      string `json:"sha256"`
	CreatedAt string `json:"created_at"`
}

// Store reads and writes the auth file. It re-reads the file whenever its
// modification time changes, so `proxygate passwd` run while the server is
// up takes effect on the next request.
type Store struct {
	dir string

	mu      sync.Mutex
	cached  File
	modTime time.Time
	size    int64
	loaded  bool
}

// NewStore returns a store for the auth files in dir (the config directory).
func NewStore(dir string) *Store {
	return &Store{dir: dir}
}

func (s *Store) authPath() string { return filepath.Join(s.dir, AuthFileName) }

// SetupCodePath is where the one-time setup code is written.
func (s *Store) SetupCodePath() string { return filepath.Join(s.dir, SetupCodeFileName) }

// Load returns the current auth file contents (zero value if absent).
func (s *Store) Load() (File, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (File, error) {
	info, err := os.Stat(s.authPath())
	if os.IsNotExist(err) {
		s.cached, s.loaded, s.modTime, s.size = File{}, true, time.Time{}, 0
		return File{}, nil
	}
	if err != nil {
		return File{}, err
	}
	if s.loaded && info.ModTime().Equal(s.modTime) && info.Size() == s.size {
		return s.cached, nil
	}
	data, err := os.ReadFile(s.authPath())
	if err != nil {
		return File{}, err
	}
	var f File
	if err := json.Unmarshal(data, &f); err != nil {
		return File{}, fmt.Errorf("parsing %s: %w", s.authPath(), err)
	}
	s.cached, s.loaded, s.modTime, s.size = f, true, info.ModTime(), info.Size()
	return f, nil
}

func (s *Store) writeLocked(f File) error {
	if err := os.MkdirAll(s.dir, 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.authPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, s.authPath()); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replacing %s: %w", s.authPath(), err)
	}
	s.loaded = false // force a re-read so modTime/size match the new file
	_, err = s.loadLocked()
	return err
}

// SetupRequired reports whether no admin password has been set yet.
func (s *Store) SetupRequired() (bool, error) {
	f, err := s.Load()
	return f.PasswordHash == "", err
}

// EnsureSetupCode creates the one-time setup code file when setup is still
// required, and returns its path. The code itself is never logged.
func (s *Store) EnsureSetupCode() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	path := s.SetupCodePath()
	if f.PasswordHash != "" {
		return "", nil
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 16 {
		return path, nil
	}
	code, err := randomString(20, "ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
	if err != nil {
		return "", err
	}
	// Grouped for readability: XXXXX-XXXXX-XXXXX-XXXXX (about 100 bits).
	grouped := code[0:5] + "-" + code[5:10] + "-" + code[10:15] + "-" + code[15:20]
	if err := os.MkdirAll(s.dir, 0750); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(grouped+"\n"), 0600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

func normalizeCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

// CompleteSetup sets the first password if code matches the setup code file.
func (s *Store) CompleteSetup(code, password string, strong bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	if f.PasswordHash != "" {
		return ErrSetupDone
	}
	data, err := os.ReadFile(s.SetupCodePath())
	if err != nil {
		return ErrBadSetupCode
	}
	want := normalizeCode(string(data))
	if want == "" || subtle.ConstantTimeCompare([]byte(normalizeCode(code)), []byte(want)) != 1 {
		return ErrBadSetupCode
	}
	if err := s.setPasswordLocked(f, password, &strong); err != nil {
		return err
	}
	os.Remove(s.SetupCodePath())
	return nil
}

// SetPassword replaces the password, signing out every session. strong, when
// non-nil, changes the password policy first. Used by `proxygate passwd`
// and the change-password endpoint.
func (s *Store) SetPassword(password string, strong *bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	if err := s.setPasswordLocked(f, password, strong); err != nil {
		return err
	}
	os.Remove(s.SetupCodePath())
	return nil
}

func (s *Store) setPasswordLocked(f File, password string, strong *bool) error {
	if strong != nil {
		f.StrongPolicy = *strong
	}
	if err := ValidatePassword(password, f.StrongPolicy); err != nil {
		return err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	f.PasswordHash = hash
	f.PasswordChangedAt = time.Now().UTC().Format(time.RFC3339)
	f.SessionEpoch++
	return s.writeLocked(f)
}

// CheckPassword verifies a login attempt.
func (s *Store) CheckPassword(password string) bool {
	f, err := s.Load()
	if err != nil || f.PasswordHash == "" {
		return false
	}
	return VerifyPassword(password, f.PasswordHash)
}

func hashToken(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// CreateToken adds an API token and returns its secret, shown once.
func (s *Store) CreateToken(name string) (string, error) {
	if !tokenNameRe.MatchString(name) {
		return "", ErrInvalidTokenName
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return "", err
	}
	for _, t := range f.Tokens {
		if t.Name == name {
			return "", ErrTokenExists
		}
	}
	secret, err := randomString(40, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	if err != nil {
		return "", err
	}
	secret = tokenPrefix + secret
	f.Tokens = append(f.Tokens, Token{Name: name, Hash: hashToken(secret), CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	if err := s.writeLocked(f); err != nil {
		return "", err
	}
	return secret, nil
}

// RevokeToken removes the named token.
func (s *Store) RevokeToken(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	for i, t := range f.Tokens {
		if t.Name == name {
			f.Tokens = append(f.Tokens[:i], f.Tokens[i+1:]...)
			return s.writeLocked(f)
		}
	}
	return ErrTokenNotFound
}

// Tokens lists API tokens (names and creation times; never secrets).
func (s *Store) Tokens() ([]Token, error) {
	f, err := s.Load()
	return f.Tokens, err
}

// CheckToken reports whether secret matches a stored API token.
func (s *Store) CheckToken(secret string) bool {
	if !strings.HasPrefix(secret, tokenPrefix) {
		return false
	}
	f, err := s.Load()
	if err != nil {
		return false
	}
	want := hashToken(secret)
	ok := false
	for _, t := range f.Tokens {
		if subtle.ConstantTimeCompare([]byte(t.Hash), []byte(want)) == 1 {
			ok = true
		}
	}
	return ok
}
