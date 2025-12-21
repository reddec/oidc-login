package utils_test

import (
	"bytes"
	"crypto/aes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reddec/oidc-login/internal/utils"
)

// generateKey generates a test 32-byte key for AES-256
func generateKey() []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i % 256)
	}
	return key
}

// TestEncryptDecryptSuccess tests successful encryption and decryption cycle
func TestEncryptDecryptSuccess(t *testing.T) {
	key := generateKey()

	originalData := []byte("Hello, World! This is a secret message.")

	// Encrypt the data
	ciphertext, err := utils.Encrypt(key, originalData)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	require.NotEqual(t, originalData, ciphertext)
	require.GreaterOrEqual(t, len(ciphertext), aes.BlockSize) // At least nonce size

	// Decrypt the data
	decryptedData, err := utils.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, originalData, decryptedData)
}

// TestEncryptInvalidKeySize tests encryption with invalid key sizes
func TestEncryptInvalidKeySize(t *testing.T) {
	originalData := []byte("test data")

	// Test with 64-byte key (invalid size)
	key64 := make([]byte, 64)
	_, err := utils.Encrypt(key64, originalData)
	assert.Error(t, err)

	// Test with empty key
	var emptyKey []byte
	_, err = utils.Encrypt(emptyKey, originalData)
	assert.Error(t, err)

	// Test with 1-byte key (invalid size)
	key1 := []byte{1}
	_, err = utils.Encrypt(key1, originalData)
	assert.Error(t, err)
}

// TestDecryptInvalidKeySize tests decryption with invalid key sizes
func TestDecryptInvalidKeySize(t *testing.T) {
	// First create valid encrypted data with a proper key
	validKey := generateKey()
	originalData := []byte("test data")
	ciphertext, err := utils.Encrypt(validKey, originalData)
	require.NoError(t, err)

	// Test with 64-byte key (invalid size)
	key64 := make([]byte, 64)
	_, err = utils.Decrypt(key64, ciphertext)
	assert.Error(t, err)

	// Test with empty key
	var emptyKey []byte
	_, err = utils.Decrypt(emptyKey, ciphertext)
	assert.Error(t, err)

	// Test with 1-byte key (invalid size)
	key1 := []byte{1}
	_, err = utils.Decrypt(key1, ciphertext)
	assert.Error(t, err)
}

// TestDecryptCorruptedData tests decryption with corrupted or invalid data
func TestDecryptCorruptedData(t *testing.T) {
	key := generateKey()

	// Test with empty data
	var emptyData []byte
	_, err := utils.Decrypt(key, emptyData)
	assert.Error(t, err)

	// Test with data shorter than nonce size
	shortData := make([]byte, 5)
	_, err = utils.Decrypt(key, shortData)
	assert.Error(t, err)

	// Test with corrupted ciphertext (valid encrypted data but modified)
	originalData := []byte("test data")
	ciphertext, err := utils.Encrypt(key, originalData)
	require.NoError(t, err)

	// Corrupt the ciphertext by modifying a byte
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[len(corrupted)-1] ^= 0xFF // Flip bits in last byte

	_, err = utils.Decrypt(key, corrupted)
	assert.Error(t, err)

	// Test with completely invalid data
	invalidData := []byte("this is not encrypted data")
	_, err = utils.Decrypt(key, invalidData)
	assert.Error(t, err)
}

// TestEncryptDecryptEmptyData tests encryption and decryption of empty data
func TestEncryptDecryptEmptyData(t *testing.T) {
	key := generateKey()

	var emptyData []byte

	// Encrypt empty data
	ciphertext, err := utils.Encrypt(key, emptyData)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext) // Should still contain nonce

	// Decrypt empty data
	decryptedData, err := utils.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, emptyData, decryptedData)
	assert.Empty(t, decryptedData)
}

// TestEncryptDecryptLargeData tests encryption and decryption of large data
func TestEncryptDecryptLargeData(t *testing.T) {
	key := generateKey()

	// Create large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Encrypt large data
	ciphertext, err := utils.Encrypt(key, largeData)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)
	assert.Greater(t, len(ciphertext), len(largeData)) // Should be larger due to nonce and overhead

	// Decrypt large data
	decryptedData, err := utils.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, largeData, decryptedData)
	assert.Equal(t, len(largeData), len(decryptedData))
}

// TestEncryptDeterministicNonce verifies that each encryption produces different ciphertext
func TestEncryptDeterministicNonce(t *testing.T) {
	key := generateKey()

	data := []byte("test data for nonce verification")

	// Encrypt the same data multiple times
	ciphertext1, err := utils.Encrypt(key, data)
	require.NoError(t, err)

	ciphertext2, err := utils.Encrypt(key, data)
	require.NoError(t, err)

	ciphertext3, err := utils.Encrypt(key, data)
	require.NoError(t, err)

	// All ciphertexts should be different due to random nonce
	assert.NotEqual(t, ciphertext1, ciphertext2)
	assert.NotEqual(t, ciphertext2, ciphertext3)
	assert.NotEqual(t, ciphertext1, ciphertext3)

	// But all should decrypt to the same original data
	decrypted1, err := utils.Decrypt(key, ciphertext1)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted1)

	decrypted2, err := utils.Decrypt(key, ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted2)

	decrypted3, err := utils.Decrypt(key, ciphertext3)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted3)
}

// TestEncryptDecryptMultipleKeys tests that different keys produce different results
func TestEncryptDecryptMultipleKeys(t *testing.T) {
	data := []byte("test data for multiple keys")

	// Generate different keys
	key1 := generateKey()
	key2 := make([]byte, 32)
	for i := range key2 {
		key2[i] = byte((i + 128) % 256)
	}

	// Encrypt with key1
	ciphertext1, err := utils.Encrypt(key1, data)
	require.NoError(t, err)

	// Encrypt with key2
	ciphertext2, err := utils.Encrypt(key2, data)
	require.NoError(t, err)

	// Ciphertexts should be different
	assert.NotEqual(t, ciphertext1, ciphertext2)

	// Can only decrypt with the correct key
	decrypted1, err := utils.Decrypt(key1, ciphertext1)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted1)

	decrypted2, err := utils.Decrypt(key2, ciphertext2)
	require.NoError(t, err)
	assert.Equal(t, data, decrypted2)

	// Cannot decrypt with wrong key
	_, err = utils.Decrypt(key2, ciphertext1)
	assert.Error(t, err)

	_, err = utils.Decrypt(key1, ciphertext2)
	assert.Error(t, err)
}

// TestEncryptNilData tests encryption and decryption of nil data
func TestEncryptNilData(t *testing.T) {
	key := generateKey()

	var nilData []byte

	// Encrypt nil data
	ciphertext, err := utils.Encrypt(key, nilData)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	// Decrypt nil data
	decryptedData, err := utils.Decrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Nil(t, decryptedData)
}

// BenchmarkEncrypt benchmarks the encryption function
func BenchmarkEncrypt(b *testing.B) {
	key := generateKey()
	data := bytes.Repeat([]byte("benchmark data "), 100) // ~1.5KB

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := utils.Encrypt(key, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecrypt benchmarks the decryption function
func BenchmarkDecrypt(b *testing.B) {
	key := generateKey()
	data := bytes.Repeat([]byte("benchmark data "), 100) // ~1.5KB
	ciphertext, err := utils.Encrypt(key, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := utils.Decrypt(key, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
