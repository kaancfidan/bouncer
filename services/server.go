package services

import (
	"log"
	"net/http"
	"reflect"

	"github.com/google/uuid"
)

// Server struct holds references to necessary services
type Server struct {
	Upstream      http.Handler
	RouteMatcher  RouteMatcher
	Authorizer    Authorizer
	Authenticator Authenticator
	proxyEnabled  bool
}

// NewServer checks if upstream is set to enable proxy behavior, then returns a new Server instance
func NewServer(upstream http.Handler, routeMatcher RouteMatcher, authorizer Authorizer, authenticator Authenticator) *Server {
	proxyEnabled := upstream != nil && !reflect.ValueOf(upstream).IsNil()

	return &Server{
		proxyEnabled:  proxyEnabled,
		Upstream:      upstream,
		RouteMatcher:  routeMatcher,
		Authorizer:    authorizer,
		Authenticator: authenticator,
	}
}

// Handle performs authentication and authorization challenges based on given configuration
// and forwards the request to the upstream server.
func (s Server) Handle(writer http.ResponseWriter, request *http.Request) {
	requestID := uuid.New()

	log.Printf("[%v] Request received: %s %s", requestID, request.Method, request.URL.Path)

	matchedPolicies, err := s.RouteMatcher.MatchRoutePolicies(request.URL.Path, request.Method)
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

	// check if the most specific route allows anonymous requests
	if s.Authorizer.IsAnonymousAllowed(matchedPolicies, request.Method) {
		log.Printf("[%v] Allowed anonymous request.", requestID)

		if s.proxyEnabled {
			s.Upstream.ServeHTTP(writer, request)
		} else {
			writer.WriteHeader(http.StatusOK)
		}

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
		log.Printf("[%v] Check for claim \"%s\" failed.", requestID, failedClaim)
		writer.WriteHeader(http.StatusForbidden)
		return
	}

	// allow
	log.Printf("[%v] Authorized.", requestID)

	if s.proxyEnabled {
		s.Upstream.ServeHTTP(writer, request)
	} else {
		writer.WriteHeader(http.StatusOK)
	}
}
