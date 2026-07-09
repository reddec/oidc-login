package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
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
		log.Fatal("all OIDC flags required")
	}

	auth, err := oidclogin.New(context.Background(), oidclogin.Config{
		IssuerURL:    issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Flows:        oidclogin.ClientCredentials, // M2M only for this example
	})
	if err != nil {
		log.Fatal(err)
	}

	// Verify allows validation without HTTP side effects (no 401 responses,
	// no redirects). Useful for JSON APIs that need structured error payloads
	// instead of the default Secure behaviour.
	http.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		idToken, err := auth.Verify(r)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "authentication required",
			})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"subject": idToken.Subject,
			"issuer":  idToken.Issuer,
		})
	})

	// Hybrid endpoint: behaves differently for authenticated vs anonymous.
	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		idToken, err := auth.Verify(r)
		if err != nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"authenticated": false,
				"message":       "public information",
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"authenticated": true,
			"subject":       idToken.Subject,
			"message":       "private information",
		})
	})

	fmt.Println("ready - try:")
	fmt.Println("  curl -H 'Authorization: Bearer <token>' http://" + binding + "/api/whoami")
	fmt.Println("  curl http://" + binding + "/api/status")
	_ = http.ListenAndServe(binding, nil)
}
