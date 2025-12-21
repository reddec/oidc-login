package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// Encrypt encrypts data using AES-256-GCM with the provided key.
// Key must be 32 bytes for AES-256. Returns ciphertext prefixed with nonce.
func Encrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, aesgcm.NonceSize(), aesgcm.NonceSize()+len(data)+aesgcm.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("read nonce: %w", err)
	}

	// Prepend nonce to ciphertext for storage
	ciphertext := aesgcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// Decrypt decrypts data encrypted with Encrypt using AES-256-GCM.
// Expects ciphertext with nonce prepended.
func Decrypt(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	if len(data) < aesgcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Extract nonce from beginning and decrypt remaining ciphertext
	return aesgcm.Open(nil, data[:aesgcm.NonceSize()], data[aesgcm.NonceSize():], nil)
}
