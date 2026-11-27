package crypto_test

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/gcis/proxygate/internal/crypto"
)

func TestNewKeyAndParseKey(t *testing.T) {
	k1, err := crypto.NewKey()
	if err != nil || len(k1) != 32 {
		t.Fatalf("NewKey: %v %d", err, len(k1))
	}
	k2, _ := crypto.NewKey()
	if hex.EncodeToString(k1) == hex.EncodeToString(k2) {
		t.Error("keys must be random")
	}
	if got, err := crypto.ParseKey(hex.EncodeToString(k1)); err != nil || hex.EncodeToString(got) != hex.EncodeToString(k1) {
		t.Errorf("round trip: %v", err)
	}
	if _, err := crypto.ParseKey("zz"); err == nil || !strings.Contains(err.Error(), "hex") {
		t.Errorf("non-hex: %v", err)
	}
	if _, err := crypto.ParseKey("abcd"); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("short key: %v", err)
	}
}

func TestEncryptDecryptErrors(t *testing.T) {
	if _, err := crypto.Encrypt([]byte("short"), "x"); err == nil {
		t.Error("Encrypt with an invalid key length must fail")
	}
	if _, err := crypto.Decrypt([]byte("short"), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); err == nil {
		t.Error("Decrypt with an invalid key length must fail")
	}
	key, _ := crypto.NewKey()
	if _, err := crypto.Decrypt(key, "!!!not base64!!!"); err == nil {
		t.Error("invalid base64 must fail")
	}
	if _, err := crypto.Decrypt(key, "AAAA"); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("short ciphertext: %v", err)
	}
	ct, err := crypto.Encrypt(key, "secret")
	if err != nil {
		t.Fatal(err)
	}
	other, _ := crypto.NewKey()
	if _, err := crypto.Decrypt(other, ct); err == nil {
		t.Error("wrong key must fail authentication")
	}
}
