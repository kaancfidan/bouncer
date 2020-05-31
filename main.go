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
	"strconv"

	"github.com/kaancfidan/bouncer/services"
)

const version = "0.0.0-VERSION" // to be replaced in CI

type flags struct {
	signingKey    string
	signingMethod string
	configPath    string
	upstreamURL   string
	listenAddress string
	validIssuer   string
	validAudience string
	expRequired   string
	nbfRequired   string
	clockSkew     string
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
		log.Fatalf("could not create server: %v", err)
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

	var clockSkew int
	if f.clockSkew != "" {
		clockSkew, err = strconv.Atoi(f.clockSkew)
		if err != nil {
			return nil, fmt.Errorf("clock skew flag %s cannot be converted to integer", f.clockSkew)
		}
	} else {
		clockSkew = 0
	}

	authenticator, err := services.NewAuthenticator(
		[]byte(f.signingKey),
		f.signingMethod,
		f.validIssuer,
		f.validAudience,
		f.expRequired != "false",
		f.nbfRequired != "false",
		clockSkew)

	if err != nil {
		return nil, fmt.Errorf("could not create authenticator: %w", err)
	}

	s := services.NewServer(
		upstream,
		services.NewRouteMatcher(cfg.RoutePolicies),
		services.NewAuthorizer(cfg.ClaimPolicies),
		authenticator)

	return s, nil
}

func parseFlags() *flags {
	f := flags{
		configPath:    "/etc/bouncer/config.yaml",
		listenAddress: ":3512",
		expRequired:   "true",
		nbfRequired:   "true",
	}
	
	printVersion := flag.Bool("v", false, "print version and exit")
	flag.StringVar(&f.signingKey, "k",
		lookupEnv("BOUNCER_SIGNING_KEY", ""),
		"cryptographic signing key")

	flag.StringVar(&f.signingMethod, "m",
		lookupEnv("BOUNCER_SIGNING_METHOD", ""),
		"signing method, accepted values = [HMAC, RSA, EC]")

	flag.StringVar(&f.configPath, "p",
		lookupEnv("BOUNCER_CONFIG_PATH", f.configPath),
		fmt.Sprintf("Config YAML path, default = %s", f.configPath))

	flag.StringVar(&f.listenAddress, "l",
		lookupEnv("BOUNCER_LISTEN_ADDRESS", f.listenAddress),
		fmt.Sprintf("listen address, default = %s", f.listenAddress))

	flag.StringVar(&f.upstreamURL, "url",
		lookupEnv("BOUNCER_UPSTREAM_URL", ""),
		"URL to be called when the request is authorized")

	flag.StringVar(&f.validIssuer, "iss",
		lookupEnv("BOUNCER_VALID_ISSUER", ""),
		fmt.Sprintf("valid token issuer"))

	flag.StringVar(&f.validAudience, "aud",
		lookupEnv("BOUNCER_VALID_AUDIENCE", ""),
		fmt.Sprintf("valid token audience"))

	flag.StringVar(&f.expRequired, "exp",
		lookupEnv("BOUNCER_REQUIRE_EXPIRATION", f.expRequired),
		fmt.Sprintf("require token expiration timestamp claims, default = %s", f.expRequired))

	flag.StringVar(&f.nbfRequired, "nbf",
		lookupEnv("BOUNCER_REQUIRE_NOT_BEFORE", f.nbfRequired),
		fmt.Sprintf("require token not before timestamp claims, default = %s", f.nbfRequired))

	flag.StringVar(&f.clockSkew, "clk",
		lookupEnv("BOUNCER_CLOCK_SKEW", f.clockSkew),
		fmt.Sprintf("require token not before timestamp claims, default = %s", f.nbfRequired))

	flag.Parse()

	if *printVersion {
		fmt.Printf("Bouncer version: %s\n", version)
		os.Exit(0)
	}

	return &f
}

func lookupEnv(key string, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
