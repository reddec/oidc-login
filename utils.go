package oidclogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/coreos/go-oidc/v3/oidc"
	"io"
	"net/http"
	"strings"
)

type tokenKey struct{}

func withToken(ctx context.Context, token *oidc.IDToken) context.Context {
	return context.WithValue(ctx, tokenKey{}, token)
}

// Token gets token from current session. If handler is not from [OIDC.Secure] then the value can be nil or invalid.
func Token(req *http.Request) *oidc.IDToken {
	if v, ok := req.Context().Value(tokenKey{}).(*oidc.IDToken); ok {
		return v
	}

	return nil
}

// User based on (in order of priority) claims: preferred_username, email, subject.
func User(token *oidc.IDToken) string {
	var claims struct {
		Username string `json:"preferred_username"`
		Email    string `json:"email"`
	}
	_ = token.Claims(&claims)
	if claims.Username != "" {
		return claims.Username
	}
	if claims.Email != "" {
		return claims.Email
	}

	return token.Subject
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randBytes(nByte int) ([]byte, error) {
	b := make([]byte, nByte)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func getHost(req *http.Request) string {
	if v := req.Header.Get("X-Forwarded-Host"); v != "" {
		return v
	}
	return req.Host
}

func getProto(req *http.Request) string {
	if v := req.Header.Get("X-Forwarded-Proto"); v != "" {
		return v
	}
	if req.TLS != nil {
		return "https"
	}
	return "http"
}

func getHeaderToken(req *http.Request) (string, bool) {
	if kind, value, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold("bearer", kind) && value != "" {
		return value, true
	}
	return "", false
}
