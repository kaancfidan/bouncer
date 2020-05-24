package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/kaancfidan/bouncer/services"
)

var (
	version       = "0.0.0-VERSION" // to be replaced in CI
	hmacKey       string
	configPath    = "/var/lib/bouncer/config.yaml"
	upstreamURL   string
	listenAddress = ":3512"
)

func main() {
	flag.StringVar(&hmacKey, "signing-key",
		lookupEnv("BOUNCER_SIGNING_KEY", ""),
		"symmetric signing key to validate tokens")

	flag.StringVar(&configPath, "config-path",
		lookupEnv("BOUNCER_CONFIG_PATH", configPath),
		fmt.Sprintf("Config YAML path, default = %s", configPath))

	flag.StringVar(&upstreamURL, "upstream-url",
		lookupEnv("BOUNCER_UPSTREAM_URL", ""),
		"URL to be called when the request is authorized")

	flag.StringVar(&listenAddress, "listen-address",
		lookupEnv("BOUNCER_LISTEN_ADDRESS", listenAddress),
		fmt.Sprintf("listen address, default = %s", listenAddress))

	// parse upstream URL
	parsedURL, err := url.Parse(upstreamURL)
	if err != nil {
		log.Fatalf("upstream url could not be parsed: %v", err)
	}

	configReader, err := os.Open(configPath)
	if err != nil {
		log.Fatalf("could not open config file: %v", err)
	}

	parser := services.YamlConfigParser{}
	cfg, err := parser.ParseConfig(configReader)
	if err != nil {
		log.Fatalf("could not parse config: %v", err)
	}

	err = services.ValidateConfig(cfg)
	if err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	server := services.Server{
		Upstream:      httputil.NewSingleHostReverseProxy(parsedURL),
		RouteMatcher:  services.NewRouteMatcher(cfg.RoutePolicies),
		Authorizer:    services.NewAuthorizer(cfg.ClaimPolicies),
		Authenticator: services.NewAuthenticator([]byte(hmacKey)),
	}

	http.HandleFunc("/", server.Proxy)

	log.Printf("Bouncer (%s) starting...", version)
	defer log.Printf("Bouncer shut down.")

	err = http.ListenAndServe(listenAddress, nil)
	log.Fatal(err)
}

func lookupEnv(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
