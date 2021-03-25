package services_test

import (
	"reflect"
	"testing"

	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func TestRouteMatcherImpl_MatchRoutePolicies(t *testing.T) {
	tests := []struct {
		name          string
		routePolicies []models.RoutePolicy
		path          string
		method        string
		want          []models.RoutePolicy
		wantErr       bool
	}{
		{
			name:          "empty config",
			routePolicies: []models.RoutePolicy{},
			want:          []models.RoutePolicy{},
			wantErr:       false,
		},
		{
			name: "glob error",
			routePolicies: []models.RoutePolicy{
				{Path: "[unmatched parantheses"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "path error",
			routePolicies: []models.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			path:    ".::this is not a valid path::.",
			want:    nil,
			wantErr: true,
		},
		{
			name: "exact matched route",
			routePolicies: []models.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			path:   "/test",
			method: "GET",
			want: []models.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "exact matched route with trailing separator in request path",
			routePolicies: []models.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			path:   "/test/",
			method: "GET",
			want: []models.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "exact matched route with trailing separator in route policy",
			routePolicies: []models.RoutePolicy{
				{Path: "/test/", Methods: []string{"GET"}},
			},
			path:   "/test",
			method: "GET",
			want: []models.RoutePolicy{
				{Path: "/test/", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "exact matched route with query parameters",
			routePolicies: []models.RoutePolicy{
				{Path: "/test/", Methods: []string{"GET"}},
			},
			path:   "/test?someBool=true&someString=test",
			method: "GET",
			want: []models.RoutePolicy{
				{Path: "/test/", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "exact matched route with spaces all around",
			routePolicies: []models.RoutePolicy{
				{Path: " /test/ ", Methods: []string{"GET"}},
			},
			path:   "/test",
			method: "GET",
			want: []models.RoutePolicy{
				{Path: " /test/ ", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "matched path without method specification",
			routePolicies: []models.RoutePolicy{
				{Path: "/test"},
			},
			path: "/test",
			want: []models.RoutePolicy{
				{Path: "/test"},
			},
			wantErr: false,
		},
		{
			name: "glob matched route",
			routePolicies: []models.RoutePolicy{
				{Path: "/*"},
			},
			path: "/test",
			want: []models.RoutePolicy{
				{Path: "/*"},
			},
			wantErr: false,
		},
		{
			name: "exact path does not match subpaths",
			routePolicies: []models.RoutePolicy{
				{Path: "/"},
			},
			path:    "/test",
			want:    []models.RoutePolicy{},
			wantErr: false,
		},
		{
			name: "single star glob does not include all subpaths",
			routePolicies: []models.RoutePolicy{
				{Path: "/test/*"},
			},
			path:    "/test/1/2",
			want:    []models.RoutePolicy{},
			wantErr: false,
		},
		{
			name: "double star glob includes all subpaths",
			routePolicies: []models.RoutePolicy{
				{Path: "/test/**"},
			},
			path: "/test/1/2",
			want: []models.RoutePolicy{
				{Path: "/test/**"},
			},
			wantErr: false,
		},
		{
			name: "glob in-between",
			routePolicies: []models.RoutePolicy{
				{Path: "/test/*/perform"},
			},
			path: "/test/1/perform",
			want: []models.RoutePolicy{
				{Path: "/test/*/perform"},
			},
			wantErr: false,
		},
		{
			name: "glob matched multiple paths",
			routePolicies: []models.RoutePolicy{
				{Path: "/*"},
				{Path: "/test"},
			},
			path: "/test",
			want: []models.RoutePolicy{
				{Path: "/*"},
				{Path: "/test"},
			},
			wantErr: false,
		},
		{
			name: "non-matching method",
			routePolicies: []models.RoutePolicy{
				{Path: "/*", Methods: []string{"GET"}},
			},
			path:    "/test",
			method:  "POST",
			want:    []models.RoutePolicy{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := services.NewRouteMatcher(tt.routePolicies)

			got, err := rm.MatchRoutePolicies(tt.path, tt.method)

			if (err != nil) != tt.wantErr {
				t.Errorf("MatchRoutePolicies() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MatchRoutePolicies() got = %v, want %v", got, tt.want)
			}
		})
	}
}
