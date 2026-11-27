// Package crypto provides AES-256-GCM encryption/decryption for ProxyGate
// configuration secrets.
//
// Keys are loaded from the PROXYGATE_CONFIG_KEY environment variable, which
// must be a 64-character lowercase hex string encoding a 32-byte key.
// Generate one with: openssl rand -hex 32
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

const keyEnvVar = "PROXYGATE_CONFIG_KEY"

// KeyFromEnv reads and validates the encryption key from the
// PROXYGATE_CONFIG_KEY environment variable.  The value must be a hex-encoded
// 32-byte (256-bit) key (64 hex characters).
func KeyFromEnv() ([]byte, error) {
	val := os.Getenv(keyEnvVar)
	if val == "" {
		return nil, fmt.Errorf("%s is not set; generate one with: openssl rand -hex 32", keyEnvVar)
	}

	key, err := ParseKey(val)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyEnvVar, err)
	}
	return key, nil
}

// ParseKey decodes a hex-encoded 32-byte key, as used by PROXYGATE_CONFIG_KEY
// and the generated secret.key file.
func ParseKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decoding key: %w (must be hex-encoded)", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key must decode to exactly 32 bytes (got %d); "+
			"generate a valid key with: openssl rand -hex 32", len(key))
	}
	return key, nil
}

// NewKey returns a fresh random 32-byte key.
func NewKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	return key, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random 12-byte nonce.
// The output is base64url-encoded (no padding) and has the format:
//
//	base64url(nonce || ciphertext || auth_tag)
func Encrypt(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize()) // 12 bytes
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generating nonce: %w", err)
	}

	// Seal appends ciphertext+auth_tag to nonce
	cipherbytes := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(cipherbytes), nil
}

// Decrypt reverses Encrypt.  It base64url-decodes the input, splits out the
// nonce, and decrypts + verifies the auth tag using AES-256-GCM.
func Decrypt(key []byte, ciphertext string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("base64 decoding ciphertext: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("creating cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("creating GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, cipherbytes := data[:nonceSize], data[nonceSize:]
	plainbytes, err := gcm.Open(nil, nonce, cipherbytes, nil)
	if err != nil {
		return "", fmt.Errorf("decrypting: %w", err)
	}

	return string(plainbytes), nil
}
