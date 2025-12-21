package oidclogin

import (
	"cmp"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/reddec/oidc-login/internal/sessions"
	"github.com/reddec/oidc-login/stores"
)

const (
	stateSize = 16
	nonceSize = 16
)

var (
	ErrSessionTokenNotFound = errors.New("session token not found")
	ErrIDTokenNotFound      = errors.New("ID token not found")
	ErrOAuthHasNoIDToken    = errors.New("no ID token in OAuth token")
	ErrOAuthStateMismatch   = errors.New("state mismatch")
	ErrOAuthNonceMismatch   = errors.New("nonce mismatch")
)

var errNotApplicable = errors.New("method not applicable")

// OAuthFlow represents set of allowed OAuth flows.
type OAuthFlow uint8

const (
	ClientCredentials OAuthFlow = 0b01 // client provides ID token in Authorization header (Bearer)
	AuthorizationCode OAuthFlow = 0b10 // UI flow with redirects. This flow will always be checked last since it can initiate redirects.
	AllFlows          OAuthFlow = AuthorizationCode | ClientCredentials
)

const (
	Prefix     string = "/oauth2/"         // default prefix for callback and logout. Can be changed by [Config.CallbackPrefix].
	CookieName        = "_session"         // default cookie name.
	SessionTTL        = 7 * 24 * time.Hour // default session TTL.
)

type Config struct {
	// OIDC URL (ex: https://example.com/realm/my-realm).
	IssuerURL string
	// OIDC client name. This value doesn't need to be super secret.
	// Not advisable to share, but not designed to be a secret.
	ClientID string
	// OIDC client secret (aka: confidential mode)
	ClientSecret string
	// (optional) list of OAuth scopes. Default is minimal required: openid - [oidc.ScopeOpenID]
	Scopes []string
	// (optional) public server URL,
	// if not set system will try to detect it by request URL, X-Forwarded-Host, and X-Forwarded-Proto which is
	// potentially is not secure and can be forged (unless there is secure forward proxy in front)
	ServerURL string
	// (optional) prefix for path for callbacks URL. Default prefix is [Prefix]
	CallbackPrefix string
	// (optional) session manager. If not set, default in-memory session store will be used.
	SessionStore sessions.Store
	// (optional) cookie name for session. Default is [CookieName]
	CookieName string
	// (optional) session TTL. Default is [SessionTTL].
	SessionTTL time.Duration
	// (optional) enable X-Forwarded-Proto support.
	TrustProxy bool
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
	// (optional) handle situation after ID token refresh.
	// Could be useful to reload profile or something related to user.
	// The callback will not be called for M2M.
	// If handler returned any error, user will be rejected with 403 code.
	PostRefresh func(writer http.ResponseWriter, req *http.Request, idToken *oidc.IDToken) error
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
	if cfg.CookieName == "" {
		cfg.CookieName = CookieName
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = SessionTTL
	}
	if cfg.SessionStore == nil {
		cfg.SessionStore = stores.NewInMemory()
	}
	if cfg.Logger == nil {
		cfg.Logger = LoggerFunc(func(level Level, message string) {
			log.Println("["+level+"]", "oidc-logger:", message)
		})
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{oidc.ScopeOpenID}
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
			Scopes:       cfg.Scopes,
		},
		verifier: provider.Verifier(&oidc.Config{
			ClientID: cfg.ClientID,
		}),
		sessions:  sessions.New[storeItem](cfg.SessionStore, cfg.CookieName, cfg.SessionTTL, cfg.TrustProxy),
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
	sessions    *sessions.CookieStore[storeItem]
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

// SecureFunc is just an alias to [OIDC.Secure] for functional handlers.
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

	session, err := svc.sessions.Get(request)
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("get session: %w", err)
	}

	if session.State.OAuthToken == nil {
		svc.unauthorizedRequest(writer, request)
		return nil, ErrSessionTokenNotFound
	}

	if session.State.IDToken == nil {
		svc.unauthorizedRequest(writer, request)
		return nil, ErrIDTokenNotFound
	}

	// try to refresh token (if needed)
	if err := svc.refreshTokenIfNeeded(writer, request, session); err != nil {
		svc.unauthorizedRequest(writer, request)
		return nil, fmt.Errorf("refresh token: %w", err)
	}

	return session.State.IDToken, nil
}

func (svc *OIDC) refreshTokenIfNeeded(writer http.ResponseWriter, request *http.Request, session *sessions.Session[storeItem]) error {
	// try to refresh token (if needed)
	newToken, err := svc.getConfig(request).TokenSource(request.Context(), session.State.OAuthToken).Token()
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return fmt.Errorf("refresh token: %w", err)
	}

	// little hack since we know internal implementation of TokenSource
	if newToken == session.State.OAuthToken {
		return nil // same token, no need to refresh
	}

	// token changed
	rawIDToken, ok := newToken.Extra("id_token").(string)
	if !ok {
		// not normal situation - we lost ID token in refresh response
		svc.unauthorizedRequest(writer, request)
		return ErrOAuthHasNoIDToken
	}

	// validate token and get ID token
	idToken, err := svc.verifier.Verify(request.Context(), rawIDToken)
	if err != nil {
		svc.unauthorizedRequest(writer, request)
		return fmt.Errorf("verify token: %w", err)
	}
	session.State.IDToken = idToken
	session.State.Hint = rawIDToken

	// call hook on post-refresh
	if err := svc.postRefresh(writer, request, session.State.IDToken); err != nil {
		svc.unauthorizedRequest(writer, request)
		return fmt.Errorf("post-refresh hook failed: %w", err)
	}

	// save new token
	if err := svc.sessions.Save(writer, request, session); err != nil {
		// ignore session error - request authorized, so we may want to process it instead of dropping.
		svc.logWarn("failed commit session after validation:", err)
	}
	return nil
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

	sitePath := request.URL.RawPath
	if request.URL.RawQuery != "" {
		sitePath += "?" + request.URL.RawQuery
	}

	session, err := svc.sessions.New()
	if err != nil {
		svc.logError("create session:", err)
		http.Error(writer, "Internal error", http.StatusInternalServerError)
		return
	}

	session.State.State = state
	session.State.Nonce = nonce
	session.State.RedirectTo = sitePath

	if err := svc.sessions.Save(writer, request, session); err != nil {
		svc.logError("save session:", err)
		http.Error(writer, "Save session", http.StatusInternalServerError)
		return
	}

	http.Redirect(writer, request, svc.getConfig(request).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("max_auth_age", "0")), http.StatusFound)
}

func (svc *OIDC) handlerCallback(writer http.ResponseWriter, request *http.Request) error {
	session, err := svc.sessions.Get(request)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}

	if request.URL.Query().Get("state") != session.State.State {
		return ErrOAuthStateMismatch
	}

	oauth2Token, err := svc.getConfig(request).Exchange(request.Context(), request.URL.Query().Get("code"))
	if err != nil {
		return fmt.Errorf("exchange token: %w", err)
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return ErrOAuthHasNoIDToken
	}

	idToken, err := svc.verifier.Verify(request.Context(), rawIDToken)
	if err != nil {
		return fmt.Errorf("verify ID token: %w", err)
	}

	if idToken.Nonce != session.State.Nonce {
		return ErrOAuthNonceMismatch
	}

	if err := svc.postAuth(writer, request, idToken); err != nil {
		return fmt.Errorf("post-auth: %w", err)
	}

	if v := writer.Header().Get("Location"); v == "" {
		// redirect to root url if postAuth didn't set location
		writer.Header().Set("Location", cmp.Or(session.State.RedirectTo, svc.getServerURL(request)))
	}

	// cleanup session to reduce size
	session.State.State = ""
	session.State.Nonce = ""
	session.State.RedirectTo = ""

	// store tokens to re-use them later
	session.State.OAuthToken = oauth2Token
	session.State.IDToken = idToken
	session.State.Hint = rawIDToken

	if err := svc.sessions.Save(writer, request, session); err != nil {
		svc.logWarn("failed commit session on callback:", err)
		return fmt.Errorf("save session: %w", err) // we cannot continue
	}

	writer.WriteHeader(http.StatusSeeOther)
	return nil
}

func (svc *OIDC) logout(writer http.ResponseWriter, request *http.Request) {
	session, err := svc.sessions.Get(request)
	if err != nil {
		svc.logWarn("get session on logout:", err)
		http.Redirect(writer, request, svc.getServerURL(request), http.StatusFound)
		return
	}

	if err := svc.sessions.Delete(request.Context(), writer, session); err != nil {
		svc.logWarn("destroy session on logout:", err)
	}

	if session.State.Hint != "" {
		svc.requestEndSession(request.Context(), session.State.Hint) // ask OIDC server to terminate session
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

func (svc *OIDC) postRefresh(writer http.ResponseWriter, request *http.Request, id *oidc.IDToken) error {
	handler := svc.config.PostRefresh
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

type storeItem struct {
	OAuthToken *oauth2.Token
	IDToken    *oidc.IDToken
	Hint       string // for logout
	RedirectTo string
	State      string
	Nonce      string
}

//nolint:gochecknoinits
func init() {
	// shim for store
	gob.Register(&oauth2.Token{})
}
