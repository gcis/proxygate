// Package auth implements admin authentication for ProxyGate: the password
// and API-token store, sessions, and login throttling. See docs/security.md.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// argon2id parameters: OWASP Password Storage Cheat Sheet, first option
// (46 MiB memory, 1 iteration, 1 thread).
const (
	argonMemoryKiB = 46 * 1024
	argonTime      = 1
	argonThreads   = 1
	argonKeyLen    = 32
	argonSaltLen   = 16
)

const (
	baselineMinLength = 8
	strongMinLength   = 12
	maxPasswordLength = 256
)

// commonPasswords is a short list of passwords that appear at the top of
// every breach corpus. Strong policy rejects them (case-insensitive).
var commonPasswords = map[string]bool{
	"password": true, "password1": true, "password12": true, "password123": true,
	"password1234": true, "passw0rd": true, "p@ssw0rd": true, "p@ssword": true,
	"12345678": true, "123456789": true, "1234567890": true, "123456789012": true,
	"qwerty123": true, "qwertyuiop": true, "qwerty123456": true, "1q2w3e4r5t": true,
	"1qaz2wsx3edc": true, "iloveyou": true, "iloveyou123": true, "admin123": true,
	"administrator": true, "letmein": true, "letmein123": true, "welcome1": true,
	"welcome123": true, "changeme": true, "changeme123": true, "trustno1": true,
	"football": true, "baseball": true, "sunshine": true, "princess": true,
	"dragon123": true, "monkey123": true, "abc12345": true, "abcd1234": true,
	"aa12345678": true, "11111111": true, "00000000": true, "88888888": true,
	"superman": true, "starwars": true, "whatever": true, "computer": true,
	"internet": true, "asdfghjkl": true, "zaq12wsx": true, "michael1": true,
}

// ValidatePassword checks pw against the baseline rules and, when strong is
// set, the strong policy (NIST SP 800-63B: length and a blocklist, no forced
// character classes).
func ValidatePassword(pw string, strong bool) error {
	n := utf8.RuneCountInString(pw)
	if n > maxPasswordLength {
		return fmt.Errorf("password must be at most %d characters", maxPasswordLength)
	}
	if !strong {
		if n < baselineMinLength {
			return fmt.Errorf("password must be at least %d characters", baselineMinLength)
		}
		return nil
	}
	if n < strongMinLength {
		return fmt.Errorf("password must be at least %d characters", strongMinLength)
	}
	lower := strings.ToLower(pw)
	if commonPasswords[lower] {
		return errors.New("that password is too common; choose another")
	}
	if strings.Contains(lower, "proxygate") {
		return errors.New(`password must not contain "proxygate"`)
	}
	if first, _ := utf8.DecodeRuneInString(pw); strings.Count(pw, string(first)) == n {
		return errors.New("password must not repeat a single character")
	}
	return nil
}

// HashPassword returns a PHC-format argon2id hash.
func HashPassword(pw string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generating salt: %w", err)
	}
	sum := argon2.IDKey([]byte(pw), salt, argonTime, argonMemoryKiB, argonThreads, argonKeyLen)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemoryKiB, argonTime, argonThreads, enc.EncodeToString(salt), enc.EncodeToString(sum)), nil
}

// VerifyPassword checks pw against a PHC-format argon2id hash in constant time.
func VerifyPassword(pw, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var mem, iters uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iters, &threads); err != nil {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err := enc.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := enc.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false
	}
	got := argon2.IDKey([]byte(pw), salt, iters, mem, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// RandomPassword returns a random password for `proxygate passwd --generate`:
// 24 characters from an unambiguous alphabet, about 135 bits.
func RandomPassword() (string, error) {
	return randomString(24, "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789")
}

func randomString(n int, alphabet string) (string, error) {
	// Rejection sampling: discard bytes above the largest multiple of the
	// alphabet size so every character is equally likely.
	limit := 256 - 256%len(alphabet)
	out := make([]byte, 0, n)
	buf := make([]byte, n*2)
	for len(out) < n {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if int(b) < limit && len(out) < n {
				out = append(out, alphabet[int(b)%len(alphabet)])
			}
		}
	}
	return string(out), nil
}
