package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/kaancfidan/bouncer/services"
)

const version = "0.0.0-VERSION" // to be replaced in CI

type flags struct {
	hmacKey       string
	configPath    string
	upstreamURL   string
	listenAddress string
}

func main() {
	f := parseFlags()

	configReader, err := os.Open(f.configPath)
	if err != nil {
		log.Fatalf("could not open config file: %v", err)
	}
	defer configReader.Close()

	server, err := newServer(f, configReader)
	if err != nil {
		log.Fatalf("server could not be created: %v", err)
	}

	http.HandleFunc("/", server.Handle)

	log.Printf("Bouncer[%s] started.", version)
	defer log.Printf("Bouncer shut down.")

	err = http.ListenAndServe(f.listenAddress, nil)
	log.Fatal(err)
}

func newServer(f *flags, configReader io.Reader) (*services.Server, error) {
	var upstream http.Handler

	if f.upstreamURL != "" {
		// parse upstream URL
		parsedURL, err := url.Parse(f.upstreamURL)
		if err != nil {
			return nil, fmt.Errorf("upstream url could not be parsed: %w", err)
		}

		if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
			return nil, fmt.Errorf("upstream url scheme must be http or https")
		}

		upstream = httputil.NewSingleHostReverseProxy(parsedURL)
	}

	parser := services.YamlConfigParser{}
	cfg, err := parser.ParseConfig(configReader)
	if err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	err = services.ValidateConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	s := services.NewServer(
		upstream,
		services.NewRouteMatcher(cfg.RoutePolicies),
		services.NewAuthorizer(cfg.ClaimPolicies),
		services.NewAuthenticator([]byte(f.hmacKey)))

	return s, nil
}

func parseFlags() *flags {
	f := flags{
		configPath:    "/etc/bouncer/config.yaml",
		listenAddress: ":3512",
	}

	flag.StringVar(&f.hmacKey, "k",
		lookupEnv("BOUNCER_SIGNING_KEY", ""),
		"symmetric signing key to validate tokens")

	flag.StringVar(&f.configPath, "p",
		lookupEnv("BOUNCER_CONFIG_PATH", f.configPath),
		fmt.Sprintf("Config YAML path, default = %s", f.configPath))

	flag.StringVar(&f.upstreamURL, "u",
		lookupEnv("BOUNCER_UPSTREAM_URL", ""),
		"URL to be called when the request is authorized")

	flag.StringVar(&f.listenAddress, "l",
		lookupEnv("BOUNCER_LISTEN_ADDRESS", f.listenAddress),
		fmt.Sprintf("listen address, default = %s", f.listenAddress))

	flag.Parse()

	return &f
}

func lookupEnv(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
