package oidclogin

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/alexedwards/scs/v2"
)

func (svc *OIDC) withSession(w http.ResponseWriter, r *http.Request, tx func(session context.Context) error) error {
	session, err := svc.getSession(r)
	if err != nil {
		return fmt.Errorf("get session: %w", err)
	}

	err = tx(session)
	if err != nil {
		return err
	}

	return svc.commitSession(session, w)
}

func (svc *OIDC) getSession(r *http.Request) (context.Context, error) {
	var token string
	cookie, err := r.Cookie(svc.config.SessionManager.Cookie.Name)
	if err == nil {
		token = cookie.Value
	}

	return svc.config.SessionManager.Load(r.Context(), token)
}

func (svc *OIDC) commitSession(session context.Context, writer http.ResponseWriter) error {
	writer.Header().Add("Vary", "Cookie")

	//nolint:exhaustive
	switch svc.config.SessionManager.Status(session) {
	case scs.Modified:
		token, expiry, err := svc.config.SessionManager.Commit(session)
		if err != nil {
			return fmt.Errorf("commit: %w", err)
		}

		svc.config.SessionManager.WriteSessionCookie(session, writer, token, expiry)
	case scs.Destroyed:
		svc.config.SessionManager.WriteSessionCookie(session, writer, "", time.Time{})
	}
	return nil
}
