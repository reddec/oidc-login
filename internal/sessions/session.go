package sessions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/reddec/oidc-login/internal/utils"
)

var ErrSessionNotFound = errors.New("session not found")

// Store is used to store session data.
// All methods should be thread-safe.
// Value is guaranteed to not be used after functions call (ie: no need for manual cloning).
type Store interface {
	// Set stores value for a given key. Replaces existent if needed.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Get returns stored value or nil if key not found.
	// Important: key not found case treated as non-error - nil, nil should be returned in this case.
	Get(ctx context.Context, key string) ([]byte, error)
	// Delete key from store. Should not return an error if the key is not found.
	Delete(ctx context.Context, key string) error
}

func New[T any](store Store, cookieName string, sessionTTL time.Duration, trustProxy bool) *CookieStore[T] {
	return &CookieStore[T]{
		store:      store,
		cookieName: cookieName,
		sessionTTL: sessionTTL,
		trustProxy: trustProxy,
	}
}

type CookieStore[T any] struct {
	store      Store
	cookieName string
	sessionTTL time.Duration
	trustProxy bool
}

func (tss *CookieStore[T]) Get(r *http.Request) (*Session[T], error) {
	var id string
	cookie, err := r.Cookie(tss.cookieName)
	if err == nil {
		id = cookie.Value
	}

	state, err := tss.getItem(r.Context(), id)
	if err != nil {
		return nil, err
	}
	return &Session[T]{
		ID:    id,
		State: state,
	}, nil
}

func (tss *CookieStore[T]) Save(writer http.ResponseWriter, req *http.Request, session *Session[T]) error {
	writer.Header().Add("Vary", "Cookie")

	if err := tss.setItem(req.Context(), session.ID, session.State, tss.sessionTTL); err != nil {
		return fmt.Errorf("save session: %w", err)
	}

	http.SetCookie(writer, &http.Cookie{
		Name:     tss.cookieName,
		Value:    session.ID,
		Path:     "/",
		Secure:   utils.HTTPInfo(req, tss.trustProxy).Proto() == "https",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(tss.sessionTTL),
	})
	return nil
}

func (tss *CookieStore[T]) Delete(ctx context.Context, writer http.ResponseWriter, session *Session[T]) error {
	http.SetCookie(writer, &http.Cookie{
		Name:     tss.cookieName,
		HttpOnly: true,
		MaxAge:   -1,
	})
	return tss.deleteItem(ctx, session.ID) // delete it after cookie removal to increase chances to clear session
}

func (tss *CookieStore[T]) DeleteUnparsed(writer http.ResponseWriter, req *http.Request) error {
	http.SetCookie(writer, &http.Cookie{
		Name:     tss.cookieName,
		HttpOnly: true,
		MaxAge:   -1,
	})
	if cookie, err := req.Cookie(tss.cookieName); err == nil {
		return tss.deleteItem(req.Context(), cookie.Value)
	}
	return nil
}

// New session with random ID and pre-created state.
// Doesn't save it to storage.
func (tss *CookieStore[T]) New() (*Session[T], error) {
	const idSize = 64
	var buf [idSize]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}
	return &Session[T]{
		ID:    hex.EncodeToString(buf[:]),
		State: new(T),
	}, nil
}

func (tss *CookieStore[T]) setItem(ctx context.Context, key string, value *T, ttl time.Duration) error {
	data, err := encodeValue(value)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	return tss.store.Set(ctx, key, data, ttl)
}

// getItem returns stored value or [ErrSessionNotFound] if not found (unlike store which returns nil in this case).
func (tss *CookieStore[T]) getItem(ctx context.Context, key string) (*T, error) {
	value, err := tss.store.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	if value == nil {
		return nil, ErrSessionNotFound
	}

	var result T
	err = decodeValue(value, &result)
	if err != nil {
		return nil, fmt.Errorf("unmarshal: %w", err)
	}
	return &result, nil
}

func (tss *CookieStore[T]) deleteItem(ctx context.Context, key string) error {
	return tss.store.Delete(ctx, key)
}

type Session[T any] struct {
	ID    string
	State *T
}

func encodeValue(value any) ([]byte, error) {
	var buf bytes.Buffer
	err := gob.NewEncoder(&buf).Encode(value)
	return buf.Bytes(), err
}

func decodeValue(data []byte, ptr any) error {
	return gob.NewDecoder(bytes.NewReader(data)).Decode(ptr)
}
