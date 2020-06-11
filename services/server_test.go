package services_test

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/kaancfidan/bouncer/mocks"
	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func TestServer_Handle(t *testing.T) {
	tests := []struct {
		name               string
		proxyEnabled       bool
		expectations       func(*http.Request, *mocks.RouteMatcher, *mocks.Authenticator, *mocks.Authorizer)
		wantUpstreamCalled bool
		wantStatusCode     int
	}{
		{
			name:         "route matching failed",
			proxyEnabled: false,
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				routeMatcher.On("MatchRoutePolicies",
					request.URL.Path, request.Method).Return(nil, fmt.Errorf("path error"))
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusInternalServerError,
		},
		{
			name:         "allow anonymous",
			proxyEnabled: false,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(true)
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusOK,
		},
		{
			name:         "proxy enabled, allow anonymous",
			proxyEnabled: true,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(true)
			},
			wantUpstreamCalled: true,
			wantStatusCode:     0,
		},
		{
			name:         "authentication - success, authorization - success",
			proxyEnabled: false,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

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
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusOK,
		},
		{
			name:         "proxy enabled, authentication - success, authorization - success",
			proxyEnabled: true,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

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
			name:         "authentication - failed",
			proxyEnabled: false,
			expectations: func(
				request *http.Request,
				routeMatcher *mocks.RouteMatcher,
				authenticator *mocks.Authenticator,
				authorizer *mocks.Authorizer) {

				// no route policy matched
				matchedRoutes := make([]models.RoutePolicy, 0)

				routeMatcher.On("MatchRoutePolicies",
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

				authorizer.On("IsAnonymousAllowed", matchedRoutes, request.Method).Return(false)

				authenticator.On("Authenticate",
					mock.Anything).Return(nil, fmt.Errorf("the guy is an imposter"))
			},
			wantUpstreamCalled: false,
			wantStatusCode:     http.StatusUnauthorized,
		},
		{
			name:         "authentication - success, authorization - failed",
			proxyEnabled: false,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

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
			name:         "error while authorization",
			proxyEnabled: false,
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
					request.URL.Path, request.Method).Return(matchedRoutes, nil)

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

			request, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Errorf("could not be create request: %v", err)
				return
			}

			var upstream *mocks.Handler
			if tt.proxyEnabled {
				upstream = &mocks.Handler{}
			}

			responseWriter := &mocks.ResponseWriter{}

			routeMatcher := &mocks.RouteMatcher{}
			authenticator := &mocks.Authenticator{}
			authorizer := &mocks.Authorizer{}

			s := services.NewServer(
				upstream,
				routeMatcher,
				authorizer,
				authenticator,
				models.ServerConfig{})

			tt.expectations(request, routeMatcher, authenticator, authorizer)

			if tt.wantUpstreamCalled {
				upstream.On("ServeHTTP", responseWriter, request).Return()
			} else {
				responseWriter.On("WriteHeader", tt.wantStatusCode).Return()

				if tt.wantStatusCode == http.StatusUnauthorized {
					responseWriter.On("Header").Return(header)
				}
			}

			s.Handle(responseWriter, request)

			if tt.wantStatusCode == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", header["Www-Authenticate"][0])
			}

			if tt.proxyEnabled {
				upstream.AssertExpectations(t)
			}

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

	headerCfg := "server:\n" +
		" originalRequestHeaders:\n" +
		"  method: X-Original-Method\n" +
		"  path: X-Original-URI\n" +
		"claimPolicies: {}\n" +
		"routePolicies:\n" +
		" - path: /**\n" +
		"   allowAnonymous: true\n" +
		" - path: /test\n" +
		"   allowAnonymous: false\n"

	signingKey := []byte("iH0dQSVASteCf0ko3E9Ae9-rb_Ob4JD4bKVZQ7cTJphLxdhkOdTyXyFpk1nCASCx")

	tests := []struct {
		name           string
		configYaml     string
		method         string
		path           string
		headers        map[string]string
		wantStatusCode int
	}{
		{
			name:           "anon example - do stuff - anonymous",
			configYaml:     defaultAnonCfg,
			method:         "POST",
			path:           "/do/some/stuff",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "anon example - destroy server - anonymous",
			configYaml:     defaultAnonCfg,
			method:         "POST",
			path:           "/destroy/server",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:           "anon example - delete - anonymous",
			configYaml:     defaultAnonCfg,
			method:         "DELETE",
			path:           "/something",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "anon example - destroy server - authenticated",
			configYaml: defaultAnonCfg,
			method:     "POST",
			path:       "/destroy/server",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UifQ." +
					"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "employee example - vacation policy - anonymous",
			configYaml:     employeeCfg,
			method:         "GET",
			path:           "/vacation/policy",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "employee example - list vacations - unauthenticated",
			configYaml:     employeeCfg,
			method:         "GET",
			path:           "/vacation",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "employee example - list vacations - does not have employee number",
			configYaml: employeeCfg,
			method:     "GET",
			path:       "/vacation",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UifQ." +
					"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y"},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:       "employee example - list vacations - has employee number",
			configYaml: employeeCfg,
			method:     "GET",
			path:       "/vacation",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
					"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "employee example - update employee - not founder",
			configYaml: employeeCfg,
			method:     "PATCH",
			path:       "/vacation/john.doe",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
					"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:       "employee example - change employee vacation - founder",
			configYaml: employeeCfg,
			method:     "PATCH",
			path:       "/vacation/john.doe",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSmFuZSBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjF9." +
					"to5t1R1URIqX0q2CoI0pms5AXb77LYG0RqdrMH44XvM",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "employee example - get salary - has employee number",
			configYaml: employeeCfg,
			method:     "GET",
			path:       "/salary",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
					"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "employee example - change salary - has employee number, not human resources",
			configYaml: employeeCfg,
			method:     "PATCH",
			path:       "/salary/john.doe",
			headers: map[string]string{"Authorization": "Bearer " +
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
				"eyJuYW1lIjoiSm9obiBEb2UiLCJlbXBsb3llZV9udW1iZXIiOjEwfQ." +
				"2nvg9meB_mJdUL9vLkZG6lolvTvTd-q_3Pe7CKdzZRA",
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:       "employee example - change salary - has employee number, human resources",
			configYaml: employeeCfg,
			method:     "PATCH",
			path:       "/salary/john.doe",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSmFuZSBEb2UiLCJlbXBsb3llZV9udW1iZXI" +
					"iOjI1LCJkZXBhcnRtZW50IjoiSHVtYW5SZXNvdXJjZXMifQ." +
					"eI5xxQmYalG6B1Iae-fvLY2j3YzltF7mx-pVAxR8bLY",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "user example - register user",
			configYaml:     userCfg,
			method:         "POST",
			path:           "/users/register",
			wantStatusCode: http.StatusOK,
		},
		{
			name:           "user example - list users without token",
			configYaml:     userCfg,
			method:         "GET",
			path:           "/users",
			wantStatusCode: http.StatusUnauthorized,
		},
		{
			name:       "user example - list users with token",
			configYaml: userCfg,
			method:     "GET",
			path:       "/users",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UifQ." +
					"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "user example - delete user without permission",
			configYaml: userCfg,
			method:     "DELETE",
			path:       "/users/kaancfidan",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UifQ." +
					"fVd54ocVD8GYRqBqTvit8aJm0tyesbocOTlOfiv_m1Y",
			},
			wantStatusCode: http.StatusForbidden,
		},
		{
			name:       "user example - delete user with permission",
			configYaml: userCfg,
			method:     "DELETE",
			path:       "/users/kaancfidan",
			headers: map[string]string{
				"Authorization": "Bearer " +
					"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
					"eyJuYW1lIjoiSm9obiBEb2UiLCJwZXJtaXNzaW9uIjoiRGVsZXRlVXNlciJ9." +
					"UfayhfqkDaLcCIr1MGU6nGpv3q5DU6lyQKt2HtwFUs0",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "header example - anonymous",
			configYaml: headerCfg,
			method:     "GET",
			path:       "/auth",
			headers: map[string]string{
				"X-Original-Method": "GET",
				"X-Original-URI":    "/",
			},
			wantStatusCode: http.StatusOK,
		},
		{
			name:       "header example - authentication failed",
			configYaml: headerCfg,
			method:     "GET",
			path:       "/auth",
			headers: map[string]string{
				"X-Original-Method": "GET",
				"X-Original-URI":    "/test",
			},
			wantStatusCode: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			buf.WriteString(tt.configYaml)

			cfg, err := services.YamlConfigParser{}.ParseConfig(&buf)
			if err != nil {
				t.Errorf("could not be create config parser: %v", err)
				return
			}

			err = services.ValidateConfig(cfg)
			if err != nil {
				t.Errorf("could not validate config: %v", err)
				return
			}

			routeMatcher := services.NewRouteMatcher(cfg.RoutePolicies)
			authorizer := services.NewAuthorizer(cfg.ClaimPolicies)
			authenticator, err := services.NewAuthenticator(
				signingKey,
				"HMAC",
				models.AuthenticationConfig{
					IgnoreExpiration: true,
					IgnoreNotBefore:  true,
				})

			if err != nil {
				t.Errorf("could not create authenticator: %v", err)
				return
			}

			s := services.NewServer(
				nil,
				routeMatcher,
				authorizer,
				authenticator,
				cfg.Server)

			req, err := http.NewRequest(tt.method, tt.path, nil)
			assert.Nil(t, err)

			for k, v := range tt.headers {
				req.Header.Add(k, v)
			}

			rr := httptest.NewRecorder()
			handler := http.HandlerFunc(s.Handle)

			handler.ServeHTTP(rr, req)

			if got := rr.Code; got != tt.wantStatusCode {
				t.Errorf("Handle returned wrong status code: got %v want %v",
					got, tt.wantStatusCode)
			}
		})
	}
}
