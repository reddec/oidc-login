# OIDC login

[![license](https://img.shields.io/github/license/reddec/oidc-login.svg)](https://github.com/reddec/oidc-login)
[![Go Reference](https://pkg.go.dev/badge/github.com/reddec/oidc-login.svg)](https://pkg.go.dev/github.com/reddec/oidc-login)

Welcome to OIDC Login, a simple and secure way to authorize your application with the OpenID Connect (OIDC) protocol.
OIDC is supported by most major platforms, including Okta, Google, Auth0, Keycloak, Authentik, and others.

OpenID Connect
([OIDC](https://auth0.com/docs/authenticate/protocols/openid-connect-protocol#:~:text=OpenID%20Connect%20(OIDC)%20is%20an,obtain%20basic%20user%20profile%20information))
is a simple identity layer on top of the OAuth 2.0 protocol that allows clients to verify the
identity of the end-user based on the authentication performed by an authorization server. OIDC provides a standard way
for clients to authenticate users, and obtain basic user profile information.

The library supports
both [Client Credentials](https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow)
(M2M)
and [Authorization Code](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow)
flow (UI).

Optionally, it supports encryption at rest for the session storage.

## Motivation

While there are several alternatives available, such
as [goth](https://github.com/markbates/goth), [authboss](https://github.com/volatiletech/authboss),
and [auth](https://github.com/go-pkgz/auth), they all have similar flaws, including global state, being very
opinionated, and having so-so support for OIDC.

At OIDC Login, we follow the UNIX-like idea of doing one thing, but doing it well. Our code is focused on being
auditable, maintainable, and flexible as much as possible.

## Usage

Checkout [Go docs](https://pkg.go.dev/github.com/reddec/oidc-login) and [examples](examples).

### Quick start

Wrap an entire mux (or handler) with `Secure` to protect all routes at once:

```go
auth, err := oidclogin.New(context.Background(), oidclogin.Config{
    IssuerURL:    "https://some-idp.example.com",
    ClientID:     "<MY CLIENT ID>",
    ClientSecret: "<MY SECRET>",
})
if err != nil {
    panic(err) // handle it properly in production
}

private := http.NewServeMux()
private.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
    name := oidclogin.User(r)
    fmt.Fprintf(w, "<html><body><h1>Hello, %s!</h1></body></html>", name)
})

// Secure the entire mux at the root. The OIDC callback (<prefix>/callback) and
// logout (<prefix>/logout) endpoints are served automatically — one mount is all
// you need.
http.Handle("/", auth.Secure(private))
```

> [!NOTE]
> **Register this redirect URI at your IdP:** `https://<public-server-url>/oauth2/callback`
> (or `<prefix>/callback` if you set a custom `Config.Prefix`). The public server URL comes from
> `Config.ServerURL`, or is auto-detected from the request if unset — see [IDP configuration](#idp-configuration).

That's the whole setup. With `Secure` mounted at `/`, every route is protected and the
callback/logout endpoints are handled internally (no separate wiring). You only need to
mount `auth` at `oidclogin.Prefix` when you wrap `Secure` around sub-routers instead of
the root — see [Multiple access levels](#multiple-access-levels).

By default, ID tokens that have expired are refreshed automatically on the next request. To refresh proactively
before expiry (avoiding latency on the first request after expiry), set `RefreshBefore`:

```go
auth, err := oidclogin.New(context.Background(), oidclogin.Config{
    IssuerURL:     "https://some-idp.example.com",
    ClientID:      "<MY CLIENT ID>",
    ClientSecret:  "<MY SECRET>",
    RefreshBefore: 5 * time.Minute, // refresh tokens 5 minutes before they expire
})
```

### Group-based access control

Pass allowed group names to `Secure` to restrict access to users belonging to at least one of those groups.
Groups are read from the `groups` claim in the ID token.

```go
// only users in the "admin" group can access this mux
http.Handle("/admin/", auth.Secure(admin, "admin"))

// users in either "editor" or "admin" group can access this mux
http.Handle("/editor/", auth.Secure(editor, "editor", "admin"))
```

Without groups, all authenticated users are allowed:

```go
http.Handle("/", auth.Secure(private))
```

For inline checks inside handlers, use the `Belongs` helper:

```go
private.HandleFunc("/action", func(w http.ResponseWriter, r *http.Request) {
    if !oidclogin.Belongs(r, "admin") {
        http.Error(w, "Forbidden", http.StatusForbidden)
        return
    }
    // ... admin-only logic
})
```

### Multiple access levels

Combine different muxes with different group restrictions:

```go
// admin-only routes
admin := http.NewServeMux()
admin.HandleFunc("/admin/settings", settingsHandler)
http.Handle("/admin/", auth.Secure(admin, "admin"))

// editor and admin routes
editor := http.NewServeMux()
editor.HandleFunc("/editor/dashboard", dashboardHandler)
http.Handle("/editor/", auth.Secure(editor, "editor", "admin"))

// open to all authenticated users
private := http.NewServeMux()
private.HandleFunc("/hello", helloHandler)
http.Handle("/", auth.Secure(private))

// since Secure wraps sub-routers (not the root), expose callback/logout at the prefix
http.Handle(oidclogin.Prefix, auth)
```

See the full example at [examples/group_membership/main.go](examples/group_membership/main.go).

### API-only verification (no redirects)

For JSON APIs or hybrid endpoints where you want structured error responses instead of the default `Secure` behavior
(login redirects or `401`/`403`), use `Verify`. It verifies the request using any enabled flow but performs only
cryptographic token verification — no HTTP responses, no redirects, no `PostAuth`/`PostRefresh`/`BeforeAuth` callbacks,
and no automatic refresh — so you keep full control of the response. It returns `ErrNotAuthenticated` when no valid
authentication is present.

```go
auth, err := oidclogin.New(context.Background(), oidclogin.Config{
    IssuerURL:    issuer,
    ClientID:     clientID,
    ClientSecret: clientSecret,
    Flows:        oidclogin.ClientCredentials, // M2M / bearer-token API
})
if err != nil {
    panic(err)
}

http.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
    idToken, err := auth.Verify(r)
    if err != nil {
        w.WriteHeader(http.StatusUnauthorized)
        return
    }
    fmt.Fprintln(w, "subject:", idToken.Subject)
})
```

See the full example at [examples/verify/main.go](examples/verify/main.go).

## IDP configuration

- Private client (PKCE not supported), both client_id and client_secret must be set
- Redirect URI must be `https://<public-server-url>/<oauth prefix>/callback` (default `https://<public-server-url>/oauth2/callback`)

## Notes to Admins

Here are some notes for administrators to keep in mind while using OIDC Login:

* Set the public server URL in case you cannot control `X-Forwarded-Host` and `X-Forwarded-Proto` headers by reverse
  proxy.
* Set persistent storage for sessions.
* Protect your application against Cross-Site Request Forgery (CSRF). Since Go 1.25 (this module targets Go 1.25+),
  the standard library provides
  [`http.CrossOriginProtection`](https://pkg.go.dev/net/http#example-CrossOriginProtection), which rejects non-safe
  cross-origin browser requests (GET, HEAD, and OPTIONS are always allowed as safe methods):

```go
mux := http.NewServeMux()
mux.Handle("/", auth.Secure(private))

// zero value is valid; register extra origins if your app is embedded on other sites
cop := http.NewCrossOriginProtection()
// _ = cop.AddTrustedOrigin("https://trusted.example.com")

http.ListenAndServe(":8080", cop.Handler(mux))
```

* It is also recommended to harden responses with OWASP headers:

```go
func SetOWASPHeaders(writer http.ResponseWriter) {
  writer.Header().Set("X-Frame-Options", "DENY") // helps with clickjacking
  writer.Header().Set("X-XSS-Protection", "0") // disable the deprecated, harmful XSS auditor
  writer.Header().Set("X-Content-Type-Options", "nosniff") // helps with content-type substitution
  writer.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin") // limits referrer leakage
}
```
