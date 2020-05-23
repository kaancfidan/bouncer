package bouncer_test

import (
	"testing"

	"github.com/kaancfidan/jwt-bouncer/bouncer"
)

func Test_authorizerImpl_Authorize(t *testing.T) {
	type args struct {
		policyNames []string
		claims      map[string]interface{}
	}

	tests := []struct {
		name            string
		claimPolicies   map[string][]bouncer.ClaimPolicy
		args            args
		wantFailedClaim string
		wantErr         bool
	}{
		{
			name:          "zero config - no claims",
			claimPolicies: map[string][]bouncer.ClaimPolicy{},
			args: args{
				policyNames: make([]string, 0),
				claims:      map[string]interface{}{},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name:          "zero config - irrelevant claims",
			claimPolicies: map[string][]bouncer.ClaimPolicy{},
			args: args{
				policyNames: make([]string, 0),
				claims: map[string]interface{}{
					"claim": "value",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name:          "non-existing policy",
			claimPolicies: map[string][]bouncer.ClaimPolicy{},
			args: args{
				policyNames: []string{"NonExistingPolicyName"},
				claims:      map[string]interface{}{},
			},
			wantFailedClaim: "",
			wantErr:         true,
		},
		{
			name: "claim exists",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"HasName": {
					bouncer.ClaimPolicy{
						Claim: "name",
					},
				},
			},
			args: args{
				policyNames: []string{"HasName"},
				claims: map[string]interface{}{
					"name": "John",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim does not exist",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"HasName": {
					bouncer.ClaimPolicy{
						Claim: "name",
					},
				},
			},
			args: args{
				policyNames: []string{"HasName"},
				claims: map[string]interface{}{
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "claim value matches",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"NamedJohn": {
					bouncer.ClaimPolicy{
						Claim: "name",
						Value: "John",
					},
				},
			},
			args: args{
				policyNames: []string{"NamedJohn"},
				claims: map[string]interface{}{
					"name": "John",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim value does not match",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"NamedJohn": {
					bouncer.ClaimPolicy{
						Claim: "name",
						Value: "John",
					},
				},
			},
			args: args{
				policyNames: []string{"NamedJohn"},
				claims: map[string]interface{}{
					"name": "Jane",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "multiple claim values match",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"SpecificJohn": {
					bouncer.ClaimPolicy{
						Claim: "name",
						Value: "John",
					},
					bouncer.ClaimPolicy{
						Claim: "last_name",
						Value: "Doe",
					},
				},
			},
			args: args{
				policyNames: []string{"SpecificJohn"},
				claims: map[string]interface{}{
					"name":      "John",
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "multiple claim values, one does not match",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"SpecificJohn": {
					bouncer.ClaimPolicy{
						Claim: "name",
						Value: "John",
					},
					bouncer.ClaimPolicy{
						Claim: "last_name",
						Value: "Doe",
					},
				},
			},
			args: args{
				policyNames: []string{"SpecificJohn"},
				claims: map[string]interface{}{
					"name":      "Jane",
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "array claim value matches",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"CanTest": {
					bouncer.ClaimPolicy{
						Claim: "permission",
						Value: "Test",
					},
				},
			},
			args: args{
				policyNames: []string{"CanTest"},
				claims: map[string]interface{}{
					"permission": []interface{}{"Test"},
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "array claim does not match",
			claimPolicies: map[string][]bouncer.ClaimPolicy{
				"CanDelete": {
					bouncer.ClaimPolicy{
						Claim: "permission",
						Value: "Delete",
					},
				},
			},
			args: args{
				policyNames: []string{"CanDelete"},
				claims: map[string]interface{}{
					"permission": []interface{}{"Test", "Add"},
				},
			},
			wantFailedClaim: "permission",
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bouncer.NewAuthorizer(tt.claimPolicies)

			gotFailedPolicy, err := a.Authorize(tt.args.policyNames, tt.args.claims)

			if (err != nil) != tt.wantErr {
				t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if gotFailedPolicy != tt.wantFailedClaim {
				t.Errorf("Authorize() = %v, want %v", gotFailedPolicy, tt.wantFailedClaim)
			}
		})
	}
}

func Test_authorizerImpl_IsAnonymousAllowed(t *testing.T) {
	tests := []struct {
		name            string
		matchedPolicies []bouncer.RoutePolicy
		want            bool
	}{
		{
			name:            "empty config",
			matchedPolicies: []bouncer.RoutePolicy{},
			want:            false,
		},
		{
			name:            "single allow",
			matchedPolicies: []bouncer.RoutePolicy{{AllowAnonymous: true}},
			want:            true,
		},
		{
			name:            "single disallow",
			matchedPolicies: []bouncer.RoutePolicy{{AllowAnonymous: false}},
			want:            false,
		},
		{
			name: "one allow one disallow",
			matchedPolicies: []bouncer.RoutePolicy{
				{AllowAnonymous: true},
				{AllowAnonymous: false},
			},
			want: false,
		},
		{
			name: "both allow",
			matchedPolicies: []bouncer.RoutePolicy{
				{AllowAnonymous: true},
				{AllowAnonymous: true},
			},
			want: true,
		},
		{
			name: "both disallow",
			matchedPolicies: []bouncer.RoutePolicy{
				{AllowAnonymous: false},
				{AllowAnonymous: false},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := bouncer.NewAuthorizer(map[string][]bouncer.ClaimPolicy{})

			if got := a.IsAnonymousAllowed(tt.matchedPolicies); got != tt.want {
				t.Errorf("IsAnonymousAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
