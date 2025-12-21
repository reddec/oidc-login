package sessions

import (
	"context"
	"crypto/sha3"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/reddec/oidc-login/internal/utils"
)

const saltPrefix = "DIS7WTtQeyXrO9EMdEh8BvdOGPFiogj1$"

// NewEncryptedStore creates a new encrypted session store wrapper.
// It requires cryptographically secure session keys (32+ bytes) - use Session.New() to generate them.
func NewEncryptedStore(store Store) Store {
	return &EncryptedStore{store: store}
}

// EncryptedStore provides encryption for session data using the session key itself as the encryption key.
//
// ⚠️ CRITICAL SECURITY REQUIREMENTS:
//   - Session keys MUST be 32+ bytes cryptographically secure random data
//   - Use Session.New() to generate proper keys - never use user-provided or predictable keys
//   - Keys shorter than 32 bytes will cause encryption failures
//
// SECURITY MODEL:
//   - The session key IS the encryption key (derived via SHA3)
//   - If the session key is unknown, data is undecryptable
//   - Storage compromise alone cannot decrypt session data
//   - Even with full database access, attackers cannot impersonate users without session keys
//
// KEY DERIVATION:
//   - Storage Key: SHA3(session_key) → hex encoded (used in underlying storage)
//   - Encryption Key: SHA3(saltPrefix + session_key) → 32 bytes (used for AES-256-GCM)
type EncryptedStore struct {
	store Store // underlying storage backend
}

// Set stores an encrypted value in the underlying storage.
func (es *EncryptedStore) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	raw := sha3.Sum256([]byte(key))
	storageKey := hex.EncodeToString(raw[:])
	encryptionKey := sha3.Sum256([]byte(saltPrefix + key))
	encryptedData, err := utils.Encrypt(encryptionKey[:], value)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return es.store.Set(ctx, storageKey, encryptedData, ttl)
}

// Get retrieves and decrypts a value from the underlying storage.
func (es *EncryptedStore) Get(ctx context.Context, key string) ([]byte, error) {
	raw := sha3.Sum256([]byte(key))
	storageKey := hex.EncodeToString(raw[:])
	encryptionKey := sha3.Sum256([]byte(saltPrefix + key))

	encryptedData, err := es.store.Get(ctx, storageKey)
	if err != nil {
		return nil, err
	}
	if encryptedData == nil {
		return nil, nil
	}
	return utils.Decrypt(encryptionKey[:], encryptedData)
}

// Delete removes a value from the underlying storage.
func (es *EncryptedStore) Delete(ctx context.Context, key string) error {
	raw := sha3.Sum256([]byte(key))
	storageKey := hex.EncodeToString(raw[:])
	return es.store.Delete(ctx, storageKey)
}
