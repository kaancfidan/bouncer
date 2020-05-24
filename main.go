package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/go-yaml/yaml"

	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func main() {
	upstreamURL, err := url.Parse(os.Getenv("BOUNCER_UPSTREAM_URL"))
	hmacKey := os.Getenv("BOUNCER_HMAC_SIGNING_KEY")
	configPath := os.Getenv("BOUNCER_CONFIG_PATH")

	if err != nil {
		log.Fatalf("upstream url could not be parsed: %v", err)
	}

	cfgData, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("could not read config file: %v", err)
	}

	cfg := models.Config{}
	err = yaml.Unmarshal(cfgData, &cfg)
	if err != nil {
		log.Fatalf("could not parse config file: %v", err)
	}

	server := services.Server{
		Upstream:      httputil.NewSingleHostReverseProxy(upstreamURL),
		RouteMatcher:  services.NewRouteMatcher(cfg.RoutePolicies),
		Authorizer:    services.NewAuthorizer(cfg.ClaimPolicies),
		Authenticator: services.NewAuthenticator([]byte(hmacKey)),
	}

	http.HandleFunc("/", server.Proxy)

	err = http.ListenAndServe(":3512", nil)

	log.Fatal(err)
}
