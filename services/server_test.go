package services_test

import (
	"fmt"
	"net/http"
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

		t.Run(tt.name, func(t *testing.T) {
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
