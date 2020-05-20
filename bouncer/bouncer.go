package bouncer

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type ClaimPolicy struct {
	Claim string
	Value string
}

type PathConfig struct {
	PathRegex  string
	Methods    []string
	PolicyName string
}

type Bouncer struct {
	ClaimPolicies map[string][]ClaimPolicy
	PathConfigs   []PathConfig
	Upstream      HttpServer
}

type HttpServer interface {
	ServeHTTP(writer http.ResponseWriter, request *http.Request)
}

func New(upstreamUrl *url.URL) Bouncer {
	return Bouncer{
		Upstream: httputil.NewSingleHostReverseProxy(upstreamUrl),
	}
}

func (b Bouncer) Proxy(writer http.ResponseWriter, request *http.Request) {
	requestId := uuid.New()
	log.Printf("[%v] Request received: %s %s", requestId, request.Method, request.RequestURI)

	matchingPathConfigs, err := findMatchingPathConfigs(b.PathConfigs, request.RequestURI, request.Method)
	if err != nil {
		log.Printf("[%v] Error occurred while matching path policies: %v", requestId, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	var policyNames []string
	for _, p := range matchingPathConfigs {
		policyNames = append(policyNames, p.PolicyName)
	}

	log.Printf("[%v] Policies matched: %v", requestId, policyNames)

	// check if allowed anonymously
	allowAnon := len(matchingPathConfigs) > 0
	for _, p := range matchingPathConfigs {
		if p.PolicyName != "AllowAnonymous" {
			allowAnon = false
			break
		}
	}

	if allowAnon {
		log.Printf("[%v] Allowed anonymous request.", requestId)
		b.Upstream.ServeHTTP(writer, request)
		return
	}

	authHeader := request.Header.Get("Authorization")

	claims, err := parseClaims(authHeader)

	if err != nil {
		log.Printf("[%v] Error while parsing token: %v", requestId, err)
		writer.Header().Add("WWW-Authenticate", "Bearer")
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	failedPolicy := b.checkClaims(matchingPathConfigs, claims)
	if failedPolicy != "" {
		log.Printf("[%v] Policy %s failed.", requestId, failedPolicy)
		writer.WriteHeader(http.StatusForbidden)
		return
	}

	b.Upstream.ServeHTTP(writer, request)
}

func (b Bouncer) checkClaims(pathConfigs []PathConfig, claims jwt.MapClaims) (failedPolicy string) {
	for _, pathConfig := range pathConfigs {
		claimPolicy := b.ClaimPolicies[pathConfig.PolicyName]

		for _, cp := range claimPolicy {
			claim, exists := claims[cp.Claim]

			if !exists {
				return pathConfig.PolicyName
			}

			// if no value specified, policy passes just by existing
			if cp.Value == "" {
				return ""
			}

			// if the matching claim in the token is an array
			// check if the array contains the expected value
			if arr, ok := claim.([]interface{}); ok {
				found := false
				for _, val := range arr {
					if val == cp.Value {
						found = true
						break
					}
				}

				if !found {
					return pathConfig.PolicyName
				}

				continue
			}

			// if the matching claim is not an array, check direct equality with expectation
			if claims[cp.Claim] != cp.Value {
				return pathConfig.PolicyName
			}
		}
	}

	return ""
}

func parseClaims(authHeader string) (jwt.MapClaims, error) {
	// check Bearer authentication
	splitToken := strings.Split(authHeader, "Bearer ")

	if len(splitToken) != 2 {
		return nil, fmt.Errorf("token could not be extracted")
	}

	accessToken := splitToken[1]

	// check claims for authorization
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(accessToken, claims, nil)

	// TODO validate token
	if err != nil {
		if _, ok := err.(*jwt.ValidationError); ok {
			if err.Error() == "no Keyfunc was provided." {
				return claims, nil
			}
		}
		return nil, fmt.Errorf("error occurred while parsing claims: %w", err)
	}

	return claims, nil
}

func findMatchingPathConfigs(pathConfigs []PathConfig, path string, method string) ([]PathConfig, error) {
	matches := make([]PathConfig, 0)
	for _, pc := range pathConfigs {
		// check if route matches
		matched, err := regexp.MatchString(pc.PathRegex, path)
		if err != nil {
			return nil, err
		}

		if !matched {
			continue
		}

		// check if method matches
		// all methods match if no method specified
		if pc.Methods == nil {
			matches = append(matches, pc)
			continue
		}

		for _, m := range pc.Methods {
			if m == method {
				matches = append(matches, pc)
				break
			}
		}
	}

	return matches, nil
}
