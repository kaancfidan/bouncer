package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
)

func main() {
	upstreamURL, err := url.Parse(os.Getenv("BOUNCER_UPSTREAM_URL"))
	hmacKey := os.Getenv("BOUNCER_HMAC_SIGNING_KEY")
	configPath := os.Getenv("BOUNCER_CONFIG_PATH")

	if err != nil {
		log.Fatalf("upstream url could not be parsed: %v", err)
	}

	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("could not read config file: %v", err)
	}

	cfg, err := bouncer.ParseConfig(data)
	if err != nil {
		log.Fatalf("could not parse config file: %v", err)
	}

	server := bouncer.Server{
		Upstream:      httputil.NewSingleHostReverseProxy(upstreamURL),
		RouteMatcher:  bouncer.NewRouteMatcher(cfg.RoutePolicies),
		Authorizer:    bouncer.NewAuthorizer(cfg.ClaimPolicies),
		Authenticator: bouncer.NewAuthenticator([]byte(hmacKey)),
	}

	http.HandleFunc("/", server.Proxy)

	err = http.ListenAndServe(":3512", nil)

	log.Fatal(err)
}
