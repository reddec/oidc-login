package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	oidclogin "github.com/reddec/oidc-login"
)

func main() {
	var clientID, clientSecret, issuer string
	flag.StringVar(&clientID, "client-id", "", "Client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "Client secret")
	flag.StringVar(&issuer, "issuer", "", "OIDC issuer URL")
	var binding string
	flag.StringVar(&binding, "bind", "127.0.0.1:8080", "HTTP server binding")
	flag.Parse()

	if clientID == "" || clientSecret == "" || issuer == "" {
		panic("all OIDC flags required")
	}

	auth, err := oidclogin.New(context.Background(), oidclogin.Config{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		panic(err) // handle it properly in production
	}

	// admin-only routes
	admin := http.NewServeMux()
	admin.HandleFunc("/admin/settings", func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Admin settings</h1></body></html>"))
	})

	// editor and admin routes
	editor := http.NewServeMux()
	editor.HandleFunc("/editor/dashboard", func(writer http.ResponseWriter, request *http.Request) {
		name := oidclogin.User(request)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Editor dashboard for " + name + "</h1></body></html>"))
	})

	// open to all authenticated users
	private := http.NewServeMux()
	private.HandleFunc("/private/hello", func(writer http.ResponseWriter, request *http.Request) {
		name := oidclogin.User(request)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Hello, " + name + "</h1></body></html>"))
	})

	// restrict each group to allowed roles
	http.Handle("/admin/", auth.Secure(admin, "admin"))
	http.Handle("/editor/", auth.Secure(editor, "editor", "admin"))
	http.Handle("/private/", auth.Secure(private))

	// add callback prefixes
	http.Handle(oidclogin.Prefix, auth)

	// start
	fmt.Println("ready")
	_ = http.ListenAndServe(binding, nil)
}
