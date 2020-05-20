package bouncer_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
	"github.com/kaancfidan/jwt-bouncer/mocks"
)

func TestBouncer_Proxy(t *testing.T) {
	type fields struct {
		ClaimPolicies map[string][]bouncer.ClaimPolicy
		PathConfigs   []bouncer.PathConfig
	}
	tests := []struct {
		name                 string
		fields               fields
		request              *http.Request
		wantHttpServerCalled bool
		wantStatusCode       int
	}{
		{
			name: "allow anonymous",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/",
						PolicyName: "AllowAnonymous",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "no bearer token - default",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs:   []bouncer.PathConfig{},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusUnauthorized,
		},
		{
			name: "no bearer token - configured path",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusUnauthorized,
		},
		{
			name: "invalid authorization header",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs:   []bouncer.PathConfig{},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"invalid header"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusUnauthorized,
		},
		{
			name: "invalid token",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs:   []bouncer.PathConfig{},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer invalidtoken"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusUnauthorized,
		},
		{
			name: "default auth",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs:   []bouncer.PathConfig{},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "default auth for unmatched method",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						Methods:    []string{"GET"},
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "POST",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "default auth for unmatched path",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						Methods:    []string{"GET"},
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/kek/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "existing claim",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"HasName": {
						bouncer.ClaimPolicy{
							Claim: "name",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "HasName",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "matching claim",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"NamedJohnDoe": {
						bouncer.ClaimPolicy{
							Claim: "name",
							Value: "John Doe",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "NamedJohnDoe",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "matching claim wrong value",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"NamedJaneDoe": {
						bouncer.ClaimPolicy{
							Claim: "name",
							Value: "Jane Doe",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "NamedJaneDoe",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusForbidden,
		},
		{
			name: "matching claim for matching method",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"NamedJohnDoe": {
						bouncer.ClaimPolicy{
							Claim: "name",
							Value: "John Doe",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						Methods:    []string{"GET"},
						PolicyName: "NamedJohnDoe",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "matching claim in array",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxN" +
						"TE2MjM5MDIyLCJwZXJtaXNzaW9uIjpbIlRlc3QiXX0.39z_SxLo9uqbG5lm8528" +
						"CbA8KltMAe2DJWvZ3LXm25U"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "matching multiple claims",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"SpecificJohnDoe": {
						bouncer.ClaimPolicy{
							Claim: "name",
							Value: "John Doe",
						},
						bouncer.ClaimPolicy{
							Claim: "sub",
							Value: "1234567890",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "SpecificJohnDoe",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: true,
			wantStatusCode:       0,
		},
		{
			name: "missing claim",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusForbidden,
		},
		{
			name: "missing claim in array",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanDelete": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Delete",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "CanDelete",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxN" +
						"TE2MjM5MDIyLCJwZXJtaXNzaW9uIjpbIlRlc3QiXX0.39z_SxLo9uqbG5lm8528" +
						"CbA8KltMAe2DJWvZ3LXm25U"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusForbidden,
		},
		{
			name: "partially matching claims",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"AdminJohnDoe": {
						bouncer.ClaimPolicy{
							Claim: "name",
							Value: "John Doe",
						},
						bouncer.ClaimPolicy{
							Claim: "role",
							Value: "Admin",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "AdminJohnDoe",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
				Header: map[string][]string{
					"Authorization": {"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
						"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0Ijox" +
						"NTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"},
				},
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusForbidden,
		},
		{
			name: "invalid path regex",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{
					"CanTest": {
						bouncer.ClaimPolicy{
							Claim: "permission",
							Value: "Test",
						},
					},
				},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "(unmatched/parantheses",
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusInternalServerError,
		},
		{
			name: "non-existing claim policy mentioned",
			fields: fields{
				ClaimPolicies: map[string][]bouncer.ClaimPolicy{},
				PathConfigs: []bouncer.PathConfig{
					{
						PathRegex:  "/test/?",
						PolicyName: "CanTest",
					},
				},
			},
			request: &http.Request{
				Method:     "GET",
				RequestURI: "/test/",
			},
			wantHttpServerCalled: false,
			wantStatusCode:       http.StatusInternalServerError,
		},
	}

	httpServer := &mocks.HttpServer{}
	responseWriter := &mocks.ResponseWriter{}
	header := http.Header{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := bouncer.Bouncer{
				ClaimPolicies: tt.fields.ClaimPolicies,
				PathConfigs:   tt.fields.PathConfigs,
				HttpServer:    httpServer,
			}

			if tt.wantHttpServerCalled {
				httpServer.On("ServeHTTP", responseWriter, tt.request).Return()
			} else {
				responseWriter.On("WriteHeader", tt.wantStatusCode).Return()
				responseWriter.On("Header").Return(header)
				httpServer.AssertNotCalled(t, "ServeHttp", responseWriter, tt.request)

			}

			b.Proxy(responseWriter, tt.request)

			responseWriter.AssertExpectations(t)
			httpServer.AssertExpectations(t)

			if tt.wantStatusCode == http.StatusUnauthorized {
				assert.Equal(t, "Bearer", header["Www-Authenticate"][0])
			}
		})
	}
}
