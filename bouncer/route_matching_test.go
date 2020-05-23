package bouncer_test

import (
	"reflect"
	"testing"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
)

func Test_routeMatcherImpl_MatchRoutePolicies(t *testing.T) {
	tests := []struct {
		name          string
		routePolicies []bouncer.RoutePolicy
		path          string
		method        string
		want          []bouncer.RoutePolicy
		wantErr       bool
	}{
		{
			name:          "empty config",
			routePolicies: []bouncer.RoutePolicy{},
			want:          []bouncer.RoutePolicy{},
			wantErr:       false,
		},
		{
			name: "glob error",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "[unmatched parantheses"},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "exact matched route",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			path:   "/test",
			method: "GET",
			want: []bouncer.RoutePolicy{
				{Path: "/test", Methods: []string{"GET"}},
			},
			wantErr: false,
		},
		{
			name: "matched path without method specification",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/test"},
			},
			path: "/test",
			want: []bouncer.RoutePolicy{
				{Path: "/test"},
			},
			wantErr: false,
		},
		{
			name: "glob matched route",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/*"},
			},
			path: "/test",
			want: []bouncer.RoutePolicy{
				{Path: "/*"},
			},
			wantErr: false,
		},
		{
			name: "single star glob does not include all subpaths",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/test/*"},
			},
			path:    "/test/1/2",
			want:    []bouncer.RoutePolicy{},
			wantErr: false,
		},
		{
			name: "double star glob includes all subpaths",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/test/**"},
			},
			path: "/test/1/2",
			want: []bouncer.RoutePolicy{
				{Path: "/test/**"},
			},
			wantErr: false,
		},
		{
			name: "glob in-between",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/test/*/perform"},
			},
			path: "/test/1/perform",
			want: []bouncer.RoutePolicy{
				{Path: "/test/*/perform"},
			},
			wantErr: false,
		},
		{
			name: "glob matched multiple paths",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/*"},
				{Path: "/test"},
			},
			path: "/test",
			want: []bouncer.RoutePolicy{
				{Path: "/*"},
				{Path: "/test"},
			},
			wantErr: false,
		},
		{
			name: "non-matching method",
			routePolicies: []bouncer.RoutePolicy{
				{Path: "/*", Methods: []string{"GET"}},
			},
			path:    "/test",
			method:  "POST",
			want:    []bouncer.RoutePolicy{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rm := bouncer.NewRouteMatcher(tt.routePolicies)

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
