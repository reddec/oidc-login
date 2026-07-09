package oidclogin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/dex"

	oidclogin "github.com/reddec/oidc-login"
)

var (
	testIssuer   string
	testClientID string
	testSecret   string
)

func TestMain(m *testing.M) {
	ctx := context.Background()

	clientID := "test-app"
	secret := "test-secret"

	// Password grant (ROPC) works with Dex's built-in password DB.
	// client_credentials requires an upstream connector (LDAP, GitHub, etc.).
	app, err := dex.NewClient(clientID,
		dex.WithClientSecret(secret),
		dex.WithClientGrantTypes("password"),
		dex.WithClientName("Test App"),
	)
	if err != nil {
		panic(fmt.Sprintf("new dex client: %v", err))
	}
	user, err := dex.NewUser("test@example.com", "testuser", "testpass")
	if err != nil {
		panic(fmt.Sprintf("new dex user: %v", err))
	}

	c, err := dex.Run(ctx,
		"dexidp/dex:master",
		dex.WithClient(app),
		dex.WithUser(user),
		dex.WithStorage(dex.StorageMemory),
	)
	if err != nil {
		panic(fmt.Sprintf("start dex: %v", err))
	}

	testIssuer = c.IssuerURL()
	testClientID = clientID
	testSecret = secret

	code := m.Run()

	if err := c.Terminate(ctx); err != nil {
		panic(fmt.Sprintf("terminate dex: %v", err))
	}
	os.Exit(code)
}

// getIDToken obtains a signed ID token from Dex via the password grant.
func getIDToken(t *testing.T) string {
	t.Helper()

	tokenURL := testIssuer + "/token"
	data := url.Values{
		"grant_type": {"password"},
		"username":   {"test@example.com"},
		"password":   {"testpass"},
		"scope":      {"openid"},
	}
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	require.NoError(t, err)

	req.SetBasicAuth(testClientID, testSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "token endpoint returned status %d: %s", resp.StatusCode, string(body))

	var tokenResp struct {
		IDToken string `json:"id_token"`
		Error   string `json:"error"`
	}
	require.NoError(t, json.Unmarshal(body, &tokenResp))
	require.Empty(t, tokenResp.Error, "token endpoint error: %s", tokenResp.Error)
	require.NotEmpty(t, tokenResp.IDToken, "no id_token in response")

	return tokenResp.IDToken
}

// newOIDCService creates an *oidclogin.OIDC pointing at the test Dex instance.
func newOIDCService(t *testing.T) *oidclogin.OIDC {
	t.Helper()

	svc, err := oidclogin.New(t.Context(), oidclogin.Config{
		IssuerURL:    testIssuer,
		ClientID:     testClientID,
		ClientSecret: testSecret,
		Flows:        oidclogin.ClientCredentials,
	})
	require.NoError(t, err)
	return svc
}

func TestVerify_NoToken(t *testing.T) {
	svc := newOIDCService(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	tok, err := svc.Verify(req)

	assert.ErrorIs(t, err, oidclogin.ErrNotAuthenticated)
	assert.Nil(t, tok)
}

func TestVerify_ValidBearerToken(t *testing.T) {
	svc := newOIDCService(t)
	rawToken := getIDToken(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	tok, err := svc.Verify(req)
	require.NoError(t, err)
	assert.NotNil(t, tok)
	assert.NotEmpty(t, tok.Subject)
}

func TestVerify_InvalidBearerToken(t *testing.T) {
	svc := newOIDCService(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")

	tok, err := svc.Verify(req)
	assert.Error(t, err)
	assert.Nil(t, tok)
}

func TestVerify_NoBearerHeader(t *testing.T) {
	svc := newOIDCService(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	// No Authorization header at all.

	tok, err := svc.Verify(req)
	assert.ErrorIs(t, err, oidclogin.ErrNotAuthenticated)
	assert.Nil(t, tok)
}

func TestVerify_DoesNotStashTokenInContext(t *testing.T) {
	svc := newOIDCService(t)
	rawToken := getIDToken(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	tok, err := svc.Verify(req)
	require.NoError(t, err)
	require.NotNil(t, tok)

	assert.Nil(t, oidclogin.Token(req), "Verify must not modify request context")
}

func TestVerify_TokenSubject(t *testing.T) {
	// With password grant, the subject is the user's unique ID.
	svc := newOIDCService(t)
	rawToken := getIDToken(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	tok, err := svc.Verify(req)
	require.NoError(t, err)
	assert.NotEmpty(t, tok.Subject, "token must have a subject claim")
}

func TestVerify_TokenIssuerAndAudience(t *testing.T) {
	svc := newOIDCService(t)
	rawToken := getIDToken(t)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)

	tok, err := svc.Verify(req)
	require.NoError(t, err)

	assert.Equal(t, testIssuer, tok.Issuer)
	assert.Contains(t, tok.Audience, testClientID)
}
