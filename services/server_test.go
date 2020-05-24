package services_test

import (
	"bytes"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/kaancfidan/bouncer/mocks"
	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func Test_Server_Proxy(t *testing.T) {
	tests := []struct {
		name               string
		expectations       func(*http.Request, *mocks.RouteMatcher, *mocks.Authenticator, *mocks.Authorizer)
		wantUpstreamCalled bool
		wantStatusCode     int
	}{
		{
			name: "route matching failed",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(nil, fmt.Errorf("path error"))
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusInternalServerError,
		},
		{
			name: "allow anonymous",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				matchedRoutes := []models.RoutePolicy{
					{
						Path:           "/",
						AllowAnonymous: true,
					},
				}

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes).Return(true)
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name: "authentication - success, authorization - success",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				// no route policy matched
				matchedRoutes := make([]models.RoutePolicy, 0)

				claims := map[string]interface{}{
					"claim": "value",
				}

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes).Return(false)

				authenticator.On("Authenticate",
					mock.Anything).Return(claims, nil)

				authorizer.On("Authorize",
					mock.MatchedBy(
						func(policyNames []string) bool {
							return len(policyNames) == 0
						}),
					claims).Return("", nil)
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name: "authentication - failed",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				// no route policy matched
				matchedRoutes := make([]models.RoutePolicy, 0)

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes).Return(false)

				authenticator.On("Authenticate",
					mock.Anything).Return(nil, fmt.Errorf("the guy is an imposter"))
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name: "authentication - success, authorization - failed",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				// no route policy matched
				matchedRoutes := []models.RoutePolicy{
					{
						Path:       "/",
						PolicyName: "SomePolicy",
					},
				}

				claims := map[string]interface{}{
					"claim": "value",
				}

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes).Return(false)

				authenticator.On("Authenticate",
					mock.Anything).Return(claims, nil)

				authorizer.On("Authorize",
					mock.MatchedBy(
						func(policyNames []string) bool {
							return len(policyNames) == 1 && policyNames[0] == "SomePolicy"
						}),
					claims).Return("SomePolicy", nil)
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusForbidden,
		},
		{
			name: "error while authorization",
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				// no route policy matched
				matchedRoutes := []models.RoutePolicy{
					{
						Path:       "/",
						PolicyName: "SomePolicy",
					},
				}

				claims := map[string]interface{}{
					"claim": "value",
				}

				routeMatcher.On("MatchRoutePolicies",
					request.RequestURI, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes).Return(false)

				authenticator.On("Authenticate",
					mock.Anything).Return(claims, nil)

				authorizer.On("Authorize",
					mock.MatchedBy(
						func(policyNames []string) bool {
							return len(policyNames) == 1 && policyNames[0] == "SomePolicy"
						}),
					claims).Return("", fmt.Errorf("SomePolicy does not exist"))
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusInternalServerError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}

			request := &http.Request{
				Method:     "GET",
				RequestURI: "/",
			}

			upstream := &mocks.Handler{}
			responseWriter := &mocks.ResponseWriter{}

			routeMatcher := &mocks.RouteMatcher{}
			authenticator := &mocks.Authenticator{}
			authorizer := &mocks.Authorizer{}

			s := services.Server{
				Upstream:      upstream,
				RouteMatcher:  routeMatcher,
				Authorizer:    authorizer,
				Authenticator: authenticator,
			}

			tt.expectations(request, routeMatcher, authenticator, authorizer)

			if tt.wantUpstreamCalled {
				upstream.On("ServeHTTP", responseWriter, request).Return()
			} else {
				responseWriter.On("WriteHeader", tt.wantStatusCode).Return()

				if tt.wantStatusCode == http.StatusUnauthorized {
					responseWriter.On("Header").Return(header)
				}
			}

			s.Proxy(responseWriter, request)

			if tt.wantStatusCode == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", header["Www-Authenticate"][0])
			}

			upstream.AssertExpectations(t)
			responseWriter.AssertExpectations(t)
			routeMatcher.AssertExpectations(t)
			authenticator.AssertExpectations(t)
			authorizer.AssertExpectations(t)
		})
	}
}

func Test_Server_Proxy_Integration(t *testing.T) {
	userCfg := "claimPolicies:\n" +
		" CanDeleteUsers:\n" +
		"  - claim: permission\n" +
		"    values: [DeleteUser]\n" +
		"routePolicies:\n" +
		" - path: /users/*\n" +
		"   methods: [DELETE]\n" +
		"   policyName: CanDeleteUsers\n" +
		" - path: /users/register\n" +
		"   methods: [POST]\n" +
		"   allowAnonymous: true\n" +
		" - path: /users\n" +
		"   methods: [GET]"

	defaultAnonCfg := "claimPolicies: {}\n" +
		"routePolicies:\n" +
		" - path: /**\n" +
		"   allowAnonymous: true\n" +
		" - path: /destroy/server\n" +
		"   allowAnonymous: false\n"

	hmacKey := []byte("iH0dQSVASteCf0ko3E9Ae9-rb_Ob4JD4bKVZQ7cTJphLxdhkOdTyXyFpk1nCASCx")

	tests := []struct {
		name               string
		configYaml         string
		request            *http.Request
		wantUpstreamCalled bool
		wantStatusCode     int
	}{
		{
			name:       "do stuff anonymously",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/do/some/stuff",
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "destroy server anonymously",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/destroy/server",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "register user",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/users/register",
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "list users without token",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/users",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "list users with token",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/users",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UifQ." +
							"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "delete user without permission",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "DELETE",
				RequestURI: "/users/kaancfidan",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UifQ." +
							"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y",
					},
				},
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusForbidden,
		},
		{
			name:       "delete user with permission",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "DELETE",
				RequestURI: "/users/kaancfidan",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UiLCJwZXJtaXNzaW9uIjoiRGVsZXRlVXNlciJ9." +
							"UfayhfqkDaLcCIr1MGU6nGpv3q5DU6lyQKt2HtwFUs0",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			buf.WriteString(tt.configYaml)

			cfg, err := services.YamlConfigParser{}.ParseConfig(&buf)
			assert.Nil(t, err)

			err = services.ValidateConfig(cfg)
			assert.Nil(t, err)

			header := http.Header{}

			upstream := &mocks.Handler{}
			responseWriter := &mocks.ResponseWriter{}

			routeMatcher := services.NewRouteMatcher(cfg.RoutePolicies)
			authorizer := services.NewAuthorizer(cfg.ClaimPolicies)
			authenticator := services.NewAuthenticator(hmacKey)

			s := services.Server{
				Upstream:      upstream,
				RouteMatcher:  routeMatcher,
				Authorizer:    authorizer,
				Authenticator: authenticator,
			}

			if tt.wantUpstreamCalled {
				upstream.On("ServeHTTP", responseWriter, tt.request).Return()
			} else {
				responseWriter.On("WriteHeader", tt.wantStatusCode).Return()

				if tt.wantStatusCode == http.StatusUnauthorized {
					responseWriter.On("Header").Return(header)
				}
			}

			s.Proxy(responseWriter, tt.request)

			upstream.AssertExpectations(t)
			responseWriter.AssertExpectations(t)
		})
	}
}
