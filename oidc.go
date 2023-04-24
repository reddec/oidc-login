package oidclogin

import (
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/alexedwards/scs/v2"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	stateSize = 16
	nonceSize = 16
)

const (
	stateKey = "state"
	nonceKey = "nonce"
	dataKey  = "data"
	idKey    = "id"
)

var errNotApplicable = errors.New("method not applicable")

// OAuthFlow represents set of allowed OAuth flows.
type OAuthFlow uint8

const (
	ClientCredentials OAuthFlow = 0b01 // client provides ID token in Authorization header (Bearer)
	AuthorizationCode OAuthFlow = 0b10 // UI flow with redirects. This flow will always be checked last since it can initiate redirects.
	AllFlows          OAuthFlow = AuthorizationCode | ClientCredentials
)

const Prefix string = "/oauth2/" // default prefix for callback and logout. Can be changed by [Config.CallbackPrefix].

type Config struct {
	// OIDC URL (ex: https://example.com/realm/my-realm).
	IssuerURL string
	// OIDC client name. This value doesn't need to be super secret.
	// Not advisable to share, but not designed to be a secret.
	ClientID string
	// OIDC client secret (aka: confidential mode)
	ClientSecret string
	// (optional) public server URL,
	// if not set system will try to detect it by request URL, X-Forwarded-Host, and X-Forwarded-Proto which is
	// potentially is not secure and can be forged (unless there is secure forward proxy in front)
	ServerURL string
	// (optional) prefix for path for callbacks URL. Default prefix is [Prefix]
	CallbackPrefix string
	// (optional) session manager. If not set, default in-memory session manager will be used.
	SessionManager *scs.SessionManager
	// (optional) handle user post-authorization.
	// If handler returned any error, user will be rejected with 403 code, otherwise it will return 303	StatusSeeOther.
	// Callback may set destination URL via Location header; if header is not set, root server URL will be used.
	// The callback always called for each header-based request (since it's stateless).
	// It's good place for claims-based filtering or sessions.
	PostAuth func(writer http.ResponseWriter, req *http.Request, idToken *oidc.IDToken) error
	// (optional) handle before user authorization (redirect to OIDC portal). The callback will not be called for M2M.
	// If handler returned any error, request will be rejected with 403 code.
	// It's a good place to save current URL in order to redirect user after authorization to the initial page.
	BeforeAuth func(writer http.ResponseWriter, req *http.Request) error
	// (optional) tune allowed authorization types. Default - AllFlows
	Flows OAuthFlow
	// (optional) logger for messages, default is to std logger
	Logger Logger
}

// New creates new service which handles OIDC (OAuth 2) authorization.
// It will fetch and cache OIDC information on init. Keys rotation will be done automatically.
//
// Service does provide automatic ID token refresh for UI flow.
func New(ctx context.Context, cfg Config) (*OIDC, error) {
	if cfg.CallbackPrefix == "" {
		cfg.CallbackPrefix = Prefix
	}
	if cfg.Flows == 0 {
		cfg.Flows = AllFlows
	}
	if cfg.SessionManager == nil {
		cfg.SessionManager = scs.New()
	}
	if cfg.Logger == nil {
		cfg.Logger = LoggerFunc(func(level Level, message string) {
			log.Println("["+level+"]", "oidc-logger:", message)
		})
	}
	cfg.CallbackPrefix = strings.TrimRight(cfg.CallbackPrefix, "/")

	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("get OIDC provider: %w", err)
	}
	//nolint:tagliatelle
	var claims struct {
		EndSessionURL string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&claims)

	svc := &OIDC{
		oauthConfig: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID},
		},
		verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		}),
		logoutURL: claims.EndSessionURL,
		config:    cfg,
	}
	mux := http.NewServeMux()
	mux.HandleFunc(svc.config.CallbackPrefix+"/callback", func(writer http.ResponseWriter, request *http.Request) {
		if err := svc.handlerCallback(writer, request); err != nil {
			svc.logError("handle callback:", err)
			writer.WriteHeader(http.StatusForbidden)
		}
	})
	mux.HandleFunc(svc.config.CallbackPrefix+"/logout", svc.logout)
	svc.mux = mux

	return svc, nil
}

type OIDC struct {
	oauthConfig oauth2.Config
	verifier    *oidc.IDTokenVerifier
	logoutURL   string
	config      Config
	mux         *http.ServeMux
}

// ServeHTTP handling routes for authorization flows:
//   - Callback: <prefix>/callback
//   - Logout: <prefix>/logout
func (svc *OIDC) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	svc.mux.ServeHTTP(writer, request)
}

// Config for OAUTH. Request is required for detecting public server URL (unless it is defined explicitly).
func (svc *OIDC) Config(req *http.Request) *oauth2.Config {
	return svc.getConfig(req)
}

// SecureFunc is just an alias to [Secure].
//
//nolint:interfacer
func (svc *OIDC) SecureFunc(next http.HandlerFunc) http.Handler {
	return svc.Secure(next)
}

// Secure handler by checking authorization state.
//
// If [ClientCredentials] enabled in [Config.Flows], and Authorization header present, service assumes [ClientCredentials] flow.
// In this case, invalid request will cause 401 if token invalid, or 403 if post-auth callback returned an error.
//
// If [AuthorizationCode] enabled in [Config.Flows], service will try [AuthorizationCode] flow. In this case, invalid request
// will cause login sequence and redirect to IDP.
//
// Current ID token get be obtained by [Token] from request.
func (svc *OIDC) Secure(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		// M2M flow
		idToken, err := svc.clientCredentials(writer, request)
		if !errors.Is(err, errNotApplicable) {
			if err != nil {
				svc.logError("failed validate access by client credentials flow:", err)
				return
			}
			if idToken != nil {
				next.ServeHTTP(writer, request.WithContext(withToken(request.Context(), idToken)))
				return
			}
		}
		// UI flow
		// note: UI flow should go always last, since it can initiate redirects.
		idToken, err = svc.codeGrant(writer, request)
		if !errors.Is(err, errNotApplicable) {
			if err != nil {
				svc.logError("failed validate access by code-grant flow:", err)
				return
			}
			if idToken != nil {
				next.ServeHTTP(writer, request.WithContext(withToken(request.Context(), idToken)))
				return
			}
		}

		// oops - all methods failed
		writer.WriteHeader(http.StatusUnauthorized)
	})
}

func (svc *OIDC) codeGrant(writer http.ResponseWriter, request *http.Request) (*oidc.IDToken, error) {
	if svc.config.Flows&AuthorizationCode == 0 {
		return nil, errNotApplicable
	}

	session, err := svc.getSession(request)
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("get session: %w", err)
	}

	currentOauthToken, ok := svc.config.SessionManager.Get(session, dataKey).(*oauth2.Token)
	if !ok {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("session token not found")
	}

	currentIDToken, ok := svc.config.SessionManager.Get(session, idKey).(string)
	if !ok {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("ID token not found")
	}

	// try to refresh token (if needed)
	newToken, err := svc.getConfig(request).TokenSource(request.Context(), currentOauthToken).Token()
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	// little hack since we know internal implementation of TokenSource
	if newToken != currentOauthToken {
		// token changed
		rawIDToken, ok := newToken.Extra("id_token").(string)
		if !ok {
			// not normal situation
			svc.unauthorizedRequest(writer, request)
			return nil, fmt.Errorf("no ID token in OAuth token")
		}
		currentIDToken = rawIDToken
	}

	// validate token and get ID token
	idToken, err := svc.verifier.Verify(request.Context(), currentIDToken)
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("verify token: %w", err)
	}

	// save new token
	svc.config.SessionManager.Put(session, dataKey, newToken)
	svc.config.SessionManager.Put(session, idKey, currentIDToken)

	if err := svc.commitSession(session, writer); err != nil {
		// ignore session error - request authorized, so we may want to process it instead of dropping.
		svc.logWarn("failed commit session after validation:", err)
	}
	return idToken, nil
}

func (svc *OIDC) clientCredentials(writer http.ResponseWriter, request *http.Request) (*oidc.IDToken, error) {
	if svc.config.Flows&ClientCredentials == 0 {
		return nil, errNotApplicable
	}
	token, ok := getHeaderToken(request)
	if !ok {
		return nil, errNotApplicable
	}

	idToken, err := svc.verifier.Verify(request.Context(), token)
	if err != nil {
		writer.WriteHeader(http.StatusUnauthorized)
		return nil, fmt.Errorf("verify token: %w", err)
	}
	if err := svc.postAuth(writer, request, idToken); err != nil {
		writer.WriteHeader(http.StatusForbidden)
		return nil, fmt.Errorf("headless post-auth: %w", err)
	}
	return idToken, nil
}

// unauthorized request will automatically redirect to OIDC login.
//
//nolint:contextcheck
func (svc *OIDC) unauthorizedRequest(writer http.ResponseWriter, request *http.Request) {
	if err := svc.beforeAuth(writer, request); err != nil {
		svc.logWarn("before auth failed:", err)
		writer.WriteHeader(http.StatusForbidden)
		return
	}

	state, err := randString(stateSize)
	if err != nil {
		svc.logError("generate state:", err)
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(nonceSize)
	if err != nil {
		svc.logError("generate nonce:", err)
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}

	err = svc.withSession(writer, request, func(session context.Context) error {
		svc.config.SessionManager.Put(session, stateKey, state)
		svc.config.SessionManager.Put(session, nonceKey, nonce)
		return nil
	})

	if err != nil {
		svc.logError("save session:", err)
		http.Error(writer, "Save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(writer, request, svc.getConfig(request).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("max_auth_age", "0")), http.StatusFound)
}

func (svc *OIDC) handlerCallback(writer http.ResponseWriter, request *http.Request) error {
	session, err := svc.getSession(request)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}
	state := svc.config.SessionManager.GetString(session, stateKey)

	if request.URL.Query().Get("state") != state {
		return fmt.Errorf("state did not match")
	}

	oauth2Token, err := svc.getConfig(request).Exchange(request.Context(), request.URL.Query().Get("code"))
	if err != nil {
		return fmt.Errorf("exchange token: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return fmt.Errorf("no id_token field in oauth2 token")
	}

	idToken, err := svc.verifier.Verify(request.Context(), rawIDToken)
	if err != nil {
		return fmt.Errorf("verify ID token: %w", err)
	}

	nonce := svc.config.SessionManager.GetString(session, nonceKey)

	if idToken.Nonce != nonce {
		return fmt.Errorf("nonce did not match")
	}

	if err := svc.postAuth(writer, request, idToken); err != nil {
		return fmt.Errorf("post-auth: %w", err)
	}

	if v := writer.Header().Get("Location"); v == "" {
		// redirect to root url if postAuth didn't set location
		writer.Header().Set("Location", svc.getServerURL(request))
	}

	// cleanup session to reduce size
	svc.config.SessionManager.Remove(session, nonceKey)
	svc.config.SessionManager.Remove(session, stateKey)

	// store tokens to re-use them later
	svc.config.SessionManager.Put(session, dataKey, oauth2Token)
	svc.config.SessionManager.Put(session, idKey, rawIDToken)

	if err := svc.commitSession(session, writer); err != nil {
		svc.logWarn("failed commit session on callback:", err)
	}

	writer.WriteHeader(http.StatusSeeOther)
	return nil
}

func (svc *OIDC) logout(writer http.ResponseWriter, request *http.Request) {
	err := svc.withSession(writer, request, func(session context.Context) error {
		hint := svc.config.SessionManager.GetString(session, idKey)
		svc.requestEndSession(request.Context(), hint) // ask OIDC server to terminate session
		return svc.config.SessionManager.Destroy(session)
	})
	if err != nil {
		svc.logWarn("destroy session on logout:", err)
	}
	http.Redirect(writer, request, svc.getServerURL(request), http.StatusFound)
}

func (svc *OIDC) getServerURL(req *http.Request) string {
	if u := svc.config.ServerURL; u != "" {
		return u
	}
	return getProto(req) + "://" + getHost(req)
}

func (svc *OIDC) getConfig(req *http.Request) *oauth2.Config {
	cp := svc.oauthConfig
	cp.RedirectURL = svc.getServerURL(req) + svc.config.CallbackPrefix + "/callback"
	return &cp
}

func (svc *OIDC) requestEndSession(ctx context.Context, rawToken string) {
	if svc.logoutURL == "" {
		svc.logInfo("IDP is not supporting logout URL")
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc.logoutURL+"?id_token_hint="+rawToken, nil)
	if err != nil {
		svc.logWarn("create logout sub-request to IDP:", err)
		return
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		svc.logWarn("execute logout sub-request to IDP:", err)
		return
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, res.Body)
}

func (svc *OIDC) beforeAuth(writer http.ResponseWriter, request *http.Request) error {
	handler := svc.config.BeforeAuth
	if handler == nil {
		return nil
	}
	return handler(writer, request)
}

func (svc *OIDC) postAuth(writer http.ResponseWriter, request *http.Request, id *oidc.IDToken) error {
	handler := svc.config.PostAuth
	if handler == nil {
		return nil
	}
	return handler(writer, request, id)
}

func (svc *OIDC) logInfo(messages ...any) {
	svc.config.Logger.Log(LogInfo, fmt.Sprint(messages...))
}

func (svc *OIDC) logWarn(messages ...any) {
	svc.config.Logger.Log(LogWarn, fmt.Sprint(messages...))
}

func (svc *OIDC) logError(messages ...any) {
	svc.config.Logger.Log(LogError, fmt.Sprint(messages...))
}

//nolint:gochecknoinits
func init() {
	// shim for store
	gob.Register(&oauth2.Token{})
}
