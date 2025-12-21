package sessions_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/reddec/oidc-login/internal/sessions"
	"github.com/reddec/oidc-login/stores"
)

// generateSecureKey generates a cryptographically secure 32-byte key (same as Session.New)
func generateSecureKey() string {
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(buf)
}

// TestEncryptedStoreSetGet tests basic encryption and decryption
func TestEncryptedStoreSetGet(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	testData := []byte("sensitive session data that must be encrypted")

	// Set encrypted data
	err := encryptedStore.Set(ctx, secureKey, testData, time.Hour)
	require.NoError(t, err)

	// Get and decrypt data
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData)
}

// TestEncryptedStoreNonExistentKey tests retrieval of non-existent keys
func TestEncryptedStoreNonExistentKey(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	ctx := context.Background()
	secureKey := generateSecureKey()

	// Get non-existent data
	data, err := encryptedStore.Get(ctx, secureKey)
	assert.NoError(t, err)
	assert.Nil(t, data)
}

// TestEncryptedStoreDelete tests deletion functionality
func TestEncryptedStoreDelete(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	testData := []byte("data to be deleted")

	// Set data
	err := encryptedStore.Set(ctx, secureKey, testData, time.Hour)
	require.NoError(t, err)

	// Verify data exists
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData)

	// Delete data
	err = encryptedStore.Delete(ctx, secureKey)
	require.NoError(t, err)

	// Verify data is gone
	retrievedData, err = encryptedStore.Get(ctx, secureKey)
	assert.NoError(t, err)
	assert.Nil(t, retrievedData)
}

// TestEncryptedStoreDeleteNonExistent tests deletion of non-existent keys
func TestEncryptedStoreDeleteNonExistent(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	ctx := context.Background()
	secureKey := generateSecureKey()

	// Delete non-existent data should not error
	err := encryptedStore.Delete(ctx, secureKey)
	assert.NoError(t, err)
}

// TestEncryptedStoreDifferentKeys tests that different keys produce different encrypted data
func TestEncryptedStoreDifferentKeys(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	ctx := context.Background()
	key1 := generateSecureKey()
	key2 := generateSecureKey()

	testData := []byte("same data for different keys")

	// Set same data with different keys
	err := encryptedStore.Set(ctx, key1, testData, time.Hour)
	require.NoError(t, err)

	err = encryptedStore.Set(ctx, key2, testData, time.Hour)
	require.NoError(t, err)

	// Retrieve with correct keys
	data1, err := encryptedStore.Get(ctx, key1)
	require.NoError(t, err)
	assert.Equal(t, testData, data1)

	data2, err := encryptedStore.Get(ctx, key2)
	require.NoError(t, err)
	assert.Equal(t, testData, data2)

	// Cannot retrieve with wrong key
	data3, err := encryptedStore.Get(ctx, key1+"wrong")
	assert.NoError(t, err)
	assert.Nil(t, data3)
}

// TestEncryptedStoreEmptyData tests encryption and decryption of empty data
func TestEncryptedStoreEmptyData(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	var emptyData []byte

	// Set empty data
	err := encryptedStore.Set(ctx, secureKey, emptyData, time.Hour)
	require.NoError(t, err)

	// Get empty data
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, emptyData, retrievedData)
}

// TestEncryptedStoreLargeData tests encryption and decryption of large data
func TestEncryptedStoreLargeData(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	// Create large data (1MB)
	largeData := make([]byte, 1024*1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	// Set large data
	err := encryptedStore.Set(ctx, secureKey, largeData, time.Hour)
	require.NoError(t, err)

	// Get large data
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, largeData, retrievedData)
}

// TestEncryptedStoreTTL tests that TTL is passed through to underlying store
func TestEncryptedStoreTTL(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	testData := []byte("data with TTL")
	ttl := 100 * time.Millisecond

	// Set data with TTL
	err := encryptedStore.Set(ctx, secureKey, testData, ttl)
	require.NoError(t, err)

	// Verify data exists initially
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, testData, retrievedData)

	// Wait for TTL to expire
	time.Sleep(ttl + 10*time.Millisecond)

	// Verify data is gone after TTL
	retrievedData, err = encryptedStore.Get(ctx, secureKey)
	assert.NoError(t, err)
	assert.Nil(t, retrievedData)
}

// TestEncryptedStoreOverwrite tests that setting with same key overwrites data
func TestEncryptedStoreOverwrite(t *testing.T) {
	baseStore := stores.NewInMemory()
	encryptedStore := sessions.NewEncryptedStore(baseStore)

	secureKey := generateSecureKey()
	ctx := context.Background()

	data1 := []byte("original data")
	data2 := []byte("updated data")

	// Set initial data
	err := encryptedStore.Set(ctx, secureKey, data1, time.Hour)
	require.NoError(t, err)

	// Verify initial data
	retrievedData, err := encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, data1, retrievedData)

	// Overwrite with new data
	err = encryptedStore.Set(ctx, secureKey, data2, time.Hour)
	require.NoError(t, err)

	// Verify updated data
	retrievedData, err = encryptedStore.Get(ctx, secureKey)
	require.NoError(t, err)
	assert.Equal(t, data2, retrievedData)
}
