package services_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/kaancfidan/bouncer/mocks"
	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func TestServer_Proxy(t *testing.T) {
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

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(true)
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

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(false)

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

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(false)

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

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(false)

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

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(false)

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

func TestIntegration(t *testing.T) {
	defaultAnonCfg := "claimPolicies: {}\n" +
		"routePolicies:\n" +
		" - path: /**\n" +
		"   allowAnonymous: true\n" +
		" - path: /**\n" +
		"   methods: [DELETE]\n" +
		"   allowAnonymous: false\n" +
		" - path: /destroy/server\n" +
		"   allowAnonymous: false\n"

	employeeCfg := "claimPolicies:\n" +
		" EmployeeOnly:\n" +
		"  - claim: employee_number\n" +
		" Founders:\n" +
		"  - claim: employee_number\n" +
		"    values: [1,2,3,4,5]\n" +
		" HumanResources:\n" +
		"  - claim: department\n" +
		"    values: [HumanResources]\n" +
		"routePolicies:\n" +
		" - path: /vacation/**\n" +
		"   policyName: EmployeeOnly\n" +
		" - path: /vacation/policy\n" +
		"   methods: [GET]\n" +
		"   allowAnonymous: true\n" +
		" - path: /vacation/*/\n" +
		"   methods: [PUT, PATCH]\n" +
		"   policyName: Founders\n" +
		" - path: /salary/**\n" +
		"   policyName: EmployeeOnly\n" +
		" - path: /salary/*/\n" +
		"   methods: [PUT, PATCH]\n" +
		"   policyName: HumanResources"

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
		"   allowAnonymous: true\n"

	hmacKey := []byte("iH0dQSVASteCf0ko3E9Ae9-rb_Ob4JD4bKVZQ7cTJphLxdhkOdTyXyFpk1nCASCx")

	tests := []struct {
		name               string
		configYaml         string
		request            *http.Request
		wantUpstreamCalled bool
		wantStatusCode     int
	}{
		{
			name:       "anon example - do stuff - anonymous",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/do/some/stuff",
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "anon example - destroy server - anonymous",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/destroy/server",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "anon example - delete - anonymous",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "DELETE",
				RequestURI: "/something",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "anon example - destroy server - authenticated",
			configYaml: defaultAnonCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/destroy/server",
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
			name:       "employee example - vacation policy - anonymous",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/vacation/policy",
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "employee example - list vacations - unauthenticated",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/vacation",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "employee example - list vacations - does not have employee number",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/vacation",
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
			name:       "employee example - list vacations - has employee number",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/vacation",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
							"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "employee example - update employee - not founder",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "PATCH",
				RequestURI: "/vacation/john.doe",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
							"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
					},
				},
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusForbidden,
		},
		{
			name:       "employee example - change employee vacation - founder",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "PATCH",
				RequestURI: "/vacation/john.doe",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSmFuZSBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjF9." +
							"to5t1R1URIqX0q2CoI0pms5AXb77LYG0RqdrMH44XvM",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "employee example - get salary - has employee number",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/salary",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
							"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "employee example - change salary - has employee number, not human resources",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "PATCH",
				RequestURI: "/salary/john.doe",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
							"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
					},
				},
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusForbidden,
		},
		{
			name:       "employee example - change salary - has employee number, human resources",
			configYaml: employeeCfg,
			request: &http.Request{
				Method:     "PATCH",
				RequestURI: "/salary/john.doe",
				Header: map[string][]string{
					"Authorization": {
						"Bearer " +
							"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSmFuZSBEb2UiLCJlbXBsb3llZV9udW1iZXI" +
							"iOjI1LCJkZXBhcnRtZW50IjoiSHVtYW5SZXNvdXJjZXMifQ." +
							"eI5xxQmYalG6B1Iae-fvLY2j3YzltF7mx-pVAxR8bLY",
					},
				},
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "user example - register user",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/users/register",
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:       "user example - list users without token",
			configYaml: userCfg,
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/users",
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:       "user example - list users with token",
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
			name:       "user example - delete user without permission",
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
			name:       "user example - delete user with permission",
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

func BenchmarkIntegration(b *testing.B) {
	log.SetOutput(ioutil.Discard)
	defer log.SetOutput(os.Stdout)

	cfg := "claimPolicies:\n" +
		" NamedJohn:\n" +
		"  - claim: name\n" +
		"    values: [John]\n" +
		" CanDelete:\n" +
		"  - claim: permission\n" +
		"    values: [Delete]\n" +
		"routePolicies:\n" +
		" - path: /**\n" +
		"   allowAnonymous: true\n" +
		" - path: /john\n" +
		"   policyName: NamedJohn\n" +
		" - path: /test\n" +
		"   methods: [DELETE]\n" +
		"   policyName: CanDelete\n"

	hmacKey := []byte("iH0dQSVASteCf0ko3E9Ae9-rb_Ob4JD4bKVZQ7cTJphLxdhkOdTyXyFpk1nCASCx")

	benchmarks := []struct {
		name    string
		request *http.Request
	}{
		{
			name: "anonymous request",
			request: &http.Request{
				RequestURI: "/",
				Method:     "GET",
			},
		},
		{
			name: "no token authentication fail",
			request: &http.Request{
				RequestURI: "/",
				Method:     "DELETE",
			},
		},
		{
			name: "invalid token authentication fail",
			request: &http.Request{
				RequestURI: "/",
				Method:     "DELETE",
				Header: map[string][]string{
					"Authorization": {"Bearer invalid"},
				},
			},
		},
		{
			name: "authenticated - no authorization policy",
			request: &http.Request{
				RequestURI: "/test",
				Method:     "GET",
				Header: map[string][]string{
					"Authorization": {
						"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiJ9." +
							"RrGFP4amlb2A4f7k73sUqtquV5GHsfRhtOTGmWS3uQY",
					},
				},
			},
		},
		{
			name: "authenticated - authorized (value claim)",
			request: &http.Request{
				RequestURI: "/john",
				Method:     "GET",
				Header: map[string][]string{
					"Authorization": {
						"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiJ9." +
							"RrGFP4amlb2A4f7k73sUqtquV5GHsfRhtOTGmWS3uQY",
					},
				},
			},
		},
		{
			name: "authenticated - authorized (array claim)",
			request: &http.Request{
				RequestURI: "/test",
				Method:     "DELETE",
				Header: map[string][]string{
					"Authorization": {
						"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
							"eyJuYW1lIjoiSm9obiIsInBlcm1pc3Npb24iOlsiQ3JlYXRlIiwiUmVhZCIsIlVwZGF0ZSIsIkRlbGV0ZSJdfQ." +
							"3Qev2YmWb9IIV2Xe_Yy2fxp6_TBTcWDt8gD19FHN5uY",
					},
				},
			},
		},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			buf := bytes.Buffer{}
			buf.WriteString(cfg)

			cfg, err := services.YamlConfigParser{}.ParseConfig(&buf)
			assert.Nil(b, err)

			err = services.ValidateConfig(cfg)
			assert.Nil(b, err)

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

			upstream.On("ServeHTTP", mock.Anything, mock.Anything).Return()
			responseWriter.On("WriteHeader", mock.Anything).Return()
			responseWriter.On("Header").Return(header)

			for i := 0; i < b.N; i++ {
				s.Proxy(responseWriter, bm.request)
			}
		})
	}
}
