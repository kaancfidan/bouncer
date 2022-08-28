package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"time"

	"github.com/kaancfidan/bouncer/services"
)

const version = "0.0.0-VERSION" // to be replaced in CI

type flags struct {
	signingKey       string
	signingAlg       string
	configPath       string
	listenAddress    string
	httpTimeoutInSec string
}

func main() {
	f := parseFlags()

	cfgFile, err := os.Open(f.configPath)
	if err != nil {
		log.Fatalf("could not open config file: %v", err)
	}

	server, err := newServer(f, cfgFile)
	if err != nil {
		log.Fatalf("could not create server: %v", err)
	}

	err = cfgFile.Close()
	if err != nil {
		log.Fatalf("could not close config reader")
	}

	timeoutInSec, err := strconv.Atoi(f.httpTimeoutInSec)
	if err != nil {
		log.Fatalf("could not convert request timeout in seconds to integer, value given: %s", f.httpTimeoutInSec)
	}

	log.Printf("Bouncer[%s] started.", version)
	defer log.Printf("Bouncer shut down.")

	err = http.ListenAndServe(
		f.listenAddress,
		http.TimeoutHandler(
			http.HandlerFunc(server.Handle),
			time.Duration(timeoutInSec)*time.Second,
			"request timed out"))

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
		f.signingAlg,
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
		configPath:       "/etc/bouncer/config.yaml",
		listenAddress:    ":3512",
		httpTimeoutInSec: "10",
	}

	printVersion := flag.Bool("v", false, "print version and exit")
	flag.StringVar(&f.signingKey, "k",
		lookupEnv("BOUNCER_SIGNING_KEY", ""),
		"cryptographic signing key")

	flag.StringVar(&f.signingAlg, "a",
		lookupEnv("BOUNCER_SIGNING_ALG", ""),
		"signing algorithm, accepted values = "+
			"[\"ES256\",\"ES256K,\"ES384\",\"ES512\",\"EdDSA\",\"HS256\","+
			"\"HS384\",\"HS512\",\"PS256\",\"PS384\",\"PS512\",\"RS256\",\"RS384\",\"RS512\"]")

	flag.StringVar(&f.configPath, "p",
		lookupEnv("BOUNCER_CONFIG_PATH", f.configPath),
		fmt.Sprintf("Config YAML path, default = %s", f.configPath))

	flag.StringVar(&f.listenAddress, "l",
		lookupEnv("BOUNCER_LISTEN_ADDRESS", f.listenAddress),
		fmt.Sprintf("listen address, default = %s", f.listenAddress))

	flag.StringVar(&f.httpTimeoutInSec, "t",
		lookupEnv("BOUNCER_REQUEST_TIMEOUT_IN_SEC", f.httpTimeoutInSec),
		fmt.Sprintf("request timeout in seconds, default = %ss", f.httpTimeoutInSec))

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
