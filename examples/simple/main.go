package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"time"

	oidclogin "github.com/reddec/oidc-login"
)

func main() {
	var clientID, clientSecret, issuer string
	flag.StringVar(&clientID, "client-id", "", "Client ID")
	flag.StringVar(&clientSecret, "client-secret", "", "Client secret")
	flag.StringVar(&issuer, "issuer", "", "OIDC issuer URL")
	var binding string
	flag.StringVar(&binding, "bind", "127.0.0.1:8080", "HTTP server binding")
	var refreshBefore time.Duration
	flag.DurationVar(&refreshBefore, "refresh-before", 5*time.Minute, "proactively refresh tokens this long before expiry")
	flag.Parse()

	if clientID == "" || clientSecret == "" || issuer == "" {
		panic("all OIDC flags required")
	}

	auth, err := oidclogin.New(context.Background(), oidclogin.Config{
		IssuerURL:     issuer,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		RefreshBefore: refreshBefore,
	})
	if err != nil {
		panic(err) // handle it properly in production
	}

	http.HandleFunc("/profile", func(writer http.ResponseWriter, request *http.Request) {
		user := oidclogin.User(request)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Hello, " + user + "!</h1></body></html>"))
	})

	// start
	fmt.Println("ready")
	_ = http.ListenAndServe(binding, auth.Secure(http.DefaultServeMux))
}
