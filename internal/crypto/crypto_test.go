// Tests for the crypto package.
package crypto

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// ─── TestEncryptDecryptRoundTrip ──────────────────────────────────────────────

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	plaintext := "super-secret-api-key"
	ciphertext, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if ciphertext == "" {
		t.Fatal("Encrypt returned empty ciphertext")
	}
	if ciphertext == plaintext {
		t.Fatal("Encrypt returned unchanged plaintext")
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if got != plaintext {
		t.Errorf("round-trip: want %q, got %q", plaintext, got)
	}
}

// ─── TestEncryptProducesUniqueCiphertexts ────────────────────────────────────

func TestEncryptProducesUniqueCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	plaintext := "same-plaintext"

	c1, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("first Encrypt: %v", err)
	}
	c2, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("second Encrypt: %v", err)
	}

	if c1 == c2 {
		t.Error("same plaintext encrypted twice produced identical ciphertexts (nonce not random)")
	}
}

// ─── TestDecryptWithWrongKeyFails ─────────────────────────────────────────────

func TestDecryptWithWrongKeyFails(t *testing.T) {
	key1 := make([]byte, 32)
	for i := range key1 {
		key1[i] = 0xAA
	}
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = 0xBB
	}

	ciphertext, err := Encrypt(key1, "secret")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = Decrypt(key2, ciphertext)
	if err == nil {
		t.Error("Decrypt with wrong key should return error, got nil")
	}
}

// ─── TestDecryptTamperedCiphertextFails ───────────────────────────────────────

func TestDecryptTamperedCiphertextFails(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 7)
	}

	ciphertext, err := Encrypt(key, "sensitive-data")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Tamper: flip the last character in the base64 string
	tampered := []byte(ciphertext)
	last := len(tampered) - 1
	if tampered[last] == 'A' {
		tampered[last] = 'B'
	} else {
		tampered[last] = 'A'
	}

	_, err = Decrypt(key, string(tampered))
	if err == nil {
		t.Error("Decrypt of tampered ciphertext should return error, got nil")
	}
}

// ─── TestKeyFromEnv ───────────────────────────────────────────────────────────

func TestKeyFromEnv(t *testing.T) {
	// 32 random bytes encoded as hex = 64 hex chars
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i * 3)
	}
	hexKey := hex.EncodeToString(raw)

	t.Setenv("PROXYGATE_CONFIG_KEY", hexKey)

	key, err := KeyFromEnv()
	if err != nil {
		t.Fatalf("KeyFromEnv: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("key length: want 32, got %d", len(key))
	}
	for i, b := range raw {
		if key[i] != b {
			t.Errorf("key[%d]: want 0x%02x, got 0x%02x", i, b, key[i])
		}
	}
}

// ─── TestKeyFromEnvMissing ────────────────────────────────────────────────────

func TestKeyFromEnvMissing(t *testing.T) {
	os.Unsetenv("PROXYGATE_CONFIG_KEY") //nolint:errcheck

	_, err := KeyFromEnv()
	if err == nil {
		t.Fatal("expected error when PROXYGATE_CONFIG_KEY is not set, got nil")
	}
	if !strings.Contains(err.Error(), "PROXYGATE_CONFIG_KEY") {
		t.Errorf("error message should mention PROXYGATE_CONFIG_KEY, got: %s", err.Error())
	}
}

// ─── TestKeyFromEnvTooShort ───────────────────────────────────────────────────

func TestKeyFromEnvTooShort(t *testing.T) {
	// Only 16 bytes → too short
	raw := make([]byte, 16)
	hexKey := hex.EncodeToString(raw)

	t.Setenv("PROXYGATE_CONFIG_KEY", hexKey)

	_, err := KeyFromEnv()
	if err == nil {
		t.Fatal("expected error for short key, got nil")
	}
}

// ─── TestEncryptEmptyString ───────────────────────────────────────────────────

func TestEncryptEmptyString(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}

	ciphertext, err := Encrypt(key, "")
	if err != nil {
		t.Fatalf("Encrypt empty string: %v", err)
	}

	got, err := Decrypt(key, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty string: %v", err)
	}
	if got != "" {
		t.Errorf("round-trip empty string: want empty, got %q", got)
	}
}
