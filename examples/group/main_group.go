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

	private := http.NewServeMux()
	private.HandleFunc("/private/hello", func(writer http.ResponseWriter, request *http.Request) {
		token := oidclogin.Token(request)
		name := oidclogin.User(token)
		writer.Header().Set("Content-Type", "text/html")
		_, _ = writer.Write([]byte("<html><body><h1>Hello, " + name + "</h1></body></html>"))
	})

	private.HandleFunc("/private/another", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("<html><body><h1>Another private page</h1></body></html>"))
	})

	// add secured group
	http.Handle("/private/", auth.Secure(private))

	// add callback prefixes
	http.Handle(oidclogin.Prefix, auth)

	// start
	fmt.Println("ready")
	_ = http.ListenAndServe(binding, nil)
}
