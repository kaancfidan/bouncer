package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/kaancfidan/bouncer/services"
)

const version = "0.0.0-VERSION" // to be replaced in CI

type flags struct {
	signingKey    string
	signingMethod string
	configPath    string
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
		log.Fatalf("could not create server: %v", err)
	}

	http.HandleFunc("/", server.Handle)

	log.Printf("Bouncer[%s] started.", version)
	defer log.Printf("Bouncer shut down.")

	err = http.ListenAndServe(f.listenAddress, nil)
	log.Fatal(err)
}

func newServer(f *flags, configReader io.Reader) (*services.Server, error) {
	parser := services.YamlConfigParser{}
	cfg, err := parser.ParseConfig(configReader)
	if err != nil {
		return nil, fmt.Errorf("could not parse config: %w", err)
	}

	err = services.ValidateConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	var upstream http.Handler
	if cfg.Server.ParsedURL != nil {
		upstream = httputil.NewSingleHostReverseProxy(cfg.Server.ParsedURL)
	}

	authenticator, err := services.NewAuthenticator(
		[]byte(f.signingKey),
		f.signingMethod,
		cfg.Authentication)

	if err != nil {
		return nil, fmt.Errorf("could not create authenticator: %w", err)
	}

	return services.NewServer(
		upstream,
		services.NewRouteMatcher(cfg.RoutePolicies),
		services.NewAuthorizer(cfg.ClaimPolicies),
		authenticator,
		cfg.Server), nil
}

func parseFlags() *flags {
	f := flags{
		configPath:    "/etc/bouncer/config.yaml",
		listenAddress: ":3512",
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
