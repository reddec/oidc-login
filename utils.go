package oidclogin

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
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
func User(req *http.Request) string {
	token, ok := req.Context().Value(tokenKey{}).(*oidc.IDToken)
	if !ok {
		return ""
	}
	//nolint:tagliatelle
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

// Email from claims. May return empty string.
func Email(req *http.Request) string {
	token, ok := req.Context().Value(tokenKey{}).(*oidc.IDToken)
	if !ok {
		return ""
	}
	var claims struct {
		Email string `json:"email"`
	}
	_ = token.Claims(&claims)
	return claims.Email
}

// Groups from claims. May return nil slice.
func Groups(req *http.Request) []string {
	token, ok := req.Context().Value(tokenKey{}).(*oidc.IDToken)
	if !ok {
		return nil
	}
	var claims struct {
		Groups []string `json:"groups"`
	}
	_ = token.Claims(&claims)
	return claims.Groups
}

// Belongs checks if the current user belongs to at least one of the given groups.
// Returns true if groups is empty or if the user's groups intersect with the provided groups.
func Belongs(req *http.Request, groups ...string) bool {
	if len(groups) == 0 {
		return true
	}
	userGroups := Groups(req)
	for _, userGroup := range userGroups {
		for _, allowed := range groups {
			if userGroup == allowed {
				return true
			}
		}
	}
	return false
}

func randString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

func getHeaderToken(req *http.Request) (string, bool) {
	if kind, value, ok := strings.Cut(req.Header.Get("Authorization"), " "); ok && strings.EqualFold("bearer", kind) && value != "" {
		return value, true
	}
	return "", false
}
