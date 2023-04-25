# OIDC login

[![license](https://img.shields.io/github/license/reddec/oidc-login.svg)](https://github.com/reddec/oidc-login)
[![](https://godoc.org/github.com/reddec/oidc-login?status.svg)](http://godoc.org/github.com/reddec/oidc-login)


Welcome to OIDC Login, a simple and secure way to authorize your application with the OpenID Connect (OIDC) protocol.
OIDC is supported by most major platforms, including Okta, Google, Auth0, Keycloak, Authentik, and others.

OpenID Connect
([OIDC](https://auth0.com/docs/authenticate/protocols/openid-connect-protocol#:~:text=OpenID%20Connect%20(OIDC)%20is%20an,obtain%20basic%20user%20profile%20information))
is a simple identity layer on top of the OAuth 2.0 protocol that allows clients to verify the
identity of the end-user based on the authen**tication performed by an authorization server. OIDC provides a standard way
for clients to authenticate users, and obtain basic user profile information.

The library supports
both [Client Credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow)
(M2M)
and [Authorization Code](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
flow (UI).

## Motivation

While there are several alternatives available, such
as [goth](https://github.com/markbates/goth), [authboss](https://github.com/volatiletech/authboss),
and [auth](https://github.com/go-pkgz/auth), they all have similar flaws, including global state, being very
opinionated, and having so-so support for OIDC.

At OIDC Login, we follow the UNIX-like idea of doing one thing, but doing it well. Our code is focused on being
auditable, maintainable, and flexible as much as possible.

## Usage

Checkout [Go docs](https://pkg.go.dev/github.com/reddec/oidc-login) and [examples](examples).

To use OIDC Login, simply follow the code below:

```go
package main

import (
	"context"
	"net/http"

	"github.com/reddec/oidc-login"
)

func main() {
	auth, err := oidclogin.New(context.Background(), oidclogin.Config{
		IssuerURL:    "https://some-idp.example.com",
		ClientID:     "<MY CLIENT ID>",
		ClientSecret: "<MY SECRET>",
	})
	if err != nil {
		panic(err) // handle it properly in production
	}

	// add secured route (or group)
	http.Handle("/", auth.SecureFunc(func(writer http.ResponseWriter, request *http.Request) {
		token := oidclogin.Token(request)
		name := oidclogin.User(token)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Hello, " + name + "</h1></body></html>"))
	}))

	// add callback prefixes
	http.Handle(oidclogin.Prefix, auth)
	// ...
}



```

## Notes to Admins

Here are some notes for administrators to keep in mind while using OIDC Login:

* Set the public server URL in case you cannot control `X-Forwarded-Host` and `X-Forwarded-Proto` headers by reverse
  proxy.
* Set persistent storage for sessions.
* It is highly recommended to secure your application by OWASP recommended headers. Here is some code you can use to set
  these headers:
*

```go
func SetOWASPHeaders(writer http.ResponseWriter) {
  writer.Header().Set("X-Frame-Options", "DENY") // helps with click hijacking
  writer.Header().Set("X-XSS-Protection", "0")
  writer.Header().Set("X-Content-Type-Options", "nosniff") // helps with content-type substitution
  writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin") // disables cross-origin requests 
}
```