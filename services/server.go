package services

import (
	"log"
	"net/http"

	"github.com/google/uuid"
)

// Server is a reverse proxy that receives requests and forwards them to the upstream server,
// if they pass authentication and authorization challenges.
type Server struct {
	Upstream      http.Handler
	RouteMatcher  RouteMatcher
	Authorizer    Authorizer
	Authenticator Authenticator
}

// Proxy performs authentication and authorization challenges based on given configuration
// and forwards the request to the upstream server.
func (s Server) Proxy(writer http.ResponseWriter, request *http.Request) {
	requestID := uuid.New()

	log.Printf("[%v] Request received: %s %s", requestID, request.Method, request.RequestURI)

	matchedPolicies, err := s.RouteMatcher.MatchRoutePolicies(request.RequestURI, request.Method)
	if err != nil {
		log.Printf("[%v] Error while matching path policies: %v", requestID, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	var matchedPolicyNames []string
	for _, r := range matchedPolicies {
		if r.PolicyName != "" {
			matchedPolicyNames = append(matchedPolicyNames, r.PolicyName)
		}
	}

	log.Printf("[%v] Policies matched: %v", requestID, matchedPolicyNames)

	// check if allowed anonymously
	if s.Authorizer.IsAnonymousAllowed(matchedPolicies) {
		log.Printf("[%v] Allowed anonymous request.", requestID)
		s.Upstream.ServeHTTP(writer, request)
		return
	}

	authHeader := request.Header.Get("Authorization")

	claims, err := s.Authenticator.Authenticate(authHeader)
	if err != nil {
		log.Printf("[%v] Error while authenticating: %v", requestID, err)
		writer.Header().Add("WWW-Authenticate", "Bearer")
		writer.WriteHeader(http.StatusUnauthorized)
		return
	}

	failedClaim, err := s.Authorizer.Authorize(matchedPolicyNames, claims)
	if err != nil {
		log.Printf("[%v] Error while authorizing: %v", requestID, err)
		writer.WriteHeader(http.StatusInternalServerError)
		return
	}

	if failedClaim != "" {
		log.Printf("[%v] Check for claim %s failed.", requestID, failedClaim)
		writer.WriteHeader(http.StatusForbidden)
		return
	}

	// allow
	s.Upstream.ServeHTTP(writer, request)
}
