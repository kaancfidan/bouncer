package services_test

import (
	"testing"

	"github.com/kaancfidan/bouncer/models"
	"github.com/kaancfidan/bouncer/services"
)

func TestAuthorizerImpl_Authorize(t *testing.T) {
	type args struct {
		policyNames []string
		claims      map[string]any
	}

	tests := []struct {
		name            string
		claimPolicies   map[string][]models.ClaimRequirement
		args            args
		wantFailedClaim string
		wantErr         bool
	}{
		{
			name:          "zero config - no claims",
			claimPolicies: map[string][]models.ClaimRequirement{},
			args: args{
				policyNames: make([]string, 0),
				claims:      map[string]any{},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name:          "zero config - irrelevant claims",
			claimPolicies: map[string][]models.ClaimRequirement{},
			args: args{
				policyNames: make([]string, 0),
				claims: map[string]any{
					"claim": "value",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name:          "non-existing policy",
			claimPolicies: map[string][]models.ClaimRequirement{},
			args: args{
				policyNames: []string{"NonExistingPolicyName"},
				claims:      map[string]any{},
			},
			wantFailedClaim: "",
			wantErr:         true,
		},
		{
			name: "claim exists",
			claimPolicies: map[string][]models.ClaimRequirement{
				"HasName": {
					models.ClaimRequirement{
						Claim: "name",
					},
				},
			},
			args: args{
				policyNames: []string{"HasName"},
				claims: map[string]any{
					"name": "John",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim does not exist",
			claimPolicies: map[string][]models.ClaimRequirement{
				"HasName": {
					models.ClaimRequirement{
						Claim: "name",
					},
				},
			},
			args: args{
				policyNames: []string{"HasName"},
				claims: map[string]any{
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "claim value matches - string",
			claimPolicies: map[string][]models.ClaimRequirement{
				"NamedJohn": {
					models.ClaimRequirement{
						Claim:  "name",
						Values: []string{"John"},
					},
				},
			},
			args: args{
				policyNames: []string{"NamedJohn"},
				claims: map[string]any{
					"name": "John",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim value matches - int",
			claimPolicies: map[string][]models.ClaimRequirement{
				"Founder": {
					models.ClaimRequirement{
						Claim:  "employee_number",
						Values: []string{"1"},
					},
				},
			},
			args: args{
				policyNames: []string{"Founder"},
				claims: map[string]any{
					"employee_number": 1,
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim value matches - bool",
			claimPolicies: map[string][]models.ClaimRequirement{
				"CanDoStuff": {
					models.ClaimRequirement{
						Claim:  "do_stuff",
						Values: []string{"true"},
					},
				},
			},
			args: args{
				policyNames: []string{"CanDoStuff"},
				claims: map[string]any{
					"do_stuff": true,
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "claim value does not match",
			claimPolicies: map[string][]models.ClaimRequirement{
				"NamedJohn": {
					models.ClaimRequirement{
						Claim:  "name",
						Values: []string{"John"},
					},
				},
			},
			args: args{
				policyNames: []string{"NamedJohn"},
				claims: map[string]any{
					"name": "Jane",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "multiple claim values match",
			claimPolicies: map[string][]models.ClaimRequirement{
				"SpecificJohn": {
					models.ClaimRequirement{
						Claim:  "name",
						Values: []string{"John"},
					},
					models.ClaimRequirement{
						Claim:  "last_name",
						Values: []string{"Doe"},
					},
				},
			},
			args: args{
				policyNames: []string{"SpecificJohn"},
				claims: map[string]any{
					"name":      "John",
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "multiple claim values, one does not match",
			claimPolicies: map[string][]models.ClaimRequirement{
				"SpecificJohn": {
					models.ClaimRequirement{
						Claim:  "name",
						Values: []string{"John"},
					},
					models.ClaimRequirement{
						Claim:  "last_name",
						Values: []string{"Doe"},
					},
				},
			},
			args: args{
				policyNames: []string{"SpecificJohn"},
				claims: map[string]any{
					"name":      "Jane",
					"last_name": "Doe",
				},
			},
			wantFailedClaim: "name",
			wantErr:         false,
		},
		{
			name: "array claim value matches",
			claimPolicies: map[string][]models.ClaimRequirement{
				"CanTest": {
					models.ClaimRequirement{
						Claim:  "permission",
						Values: []string{"Test"},
					},
				},
			},
			args: args{
				policyNames: []string{"CanTest"},
				claims: map[string]any{
					"permission": []any{"Test"},
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "array claim does not match",
			claimPolicies: map[string][]models.ClaimRequirement{
				"CanDelete": {
					models.ClaimRequirement{
						Claim:  "permission",
						Values: []string{"Delete"},
					},
				},
			},
			args: args{
				policyNames: []string{"CanDelete"},
				claims: map[string]any{
					"permission": []any{"Test", "Add"},
				},
			},
			wantFailedClaim: "permission",
			wantErr:         false,
		},
		{
			name: "value claim match to array",
			claimPolicies: map[string][]models.ClaimRequirement{
				"CanAddOrDelete": {
					models.ClaimRequirement{
						Claim:  "permission",
						Values: []string{"Add", "Delete"},
					},
				},
			},
			args: args{
				policyNames: []string{"CanAddOrDelete"},
				claims: map[string]any{
					"permission": "Add",
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
		{
			name: "array claim match to array",
			claimPolicies: map[string][]models.ClaimRequirement{
				"CanAddOrDelete": {
					models.ClaimRequirement{
						Claim:  "permission",
						Values: []string{"Add", "Delete"},
					},
				},
			},
			args: args{
				policyNames: []string{"CanAddOrDelete"},
				claims: map[string]any{
					"permission": []any{"Test", "Add"},
				},
			},
			wantFailedClaim: "",
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := services.NewAuthorizer(tt.claimPolicies)

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

func TestAuthorizerImpl_IsAnonymousAllowed(t *testing.T) {
	tests := []struct {
		name            string
		matchedPolicies []models.RoutePolicy
		method          string
		want            bool
	}{
		{
			name:            "no matching policies",
			matchedPolicies: []models.RoutePolicy{},
			method:          "GET",
			want:            false,
		},
		{
			name: "single matching policy - not allowed",
			matchedPolicies: []models.RoutePolicy{
				{AllowAnonymous: false},
			},
			method: "GET",
			want:   false,
		},
		{
			name: "single matching policy - allowed",
			matchedPolicies: []models.RoutePolicy{
				{AllowAnonymous: true},
			},
			method: "GET",
			want:   true,
		},
		{
			name: "multiple matching policy - different specifity",
			matchedPolicies: []models.RoutePolicy{
				{
					Path:           "/test",
					AllowAnonymous: false,
				},
				{
					Path:           "/**",
					AllowAnonymous: true,
				},
			},
			method: "GET",
			want:   false,
		},
		{
			name: "multiple matching policy - same specifity - first match is correct",
			matchedPolicies: []models.RoutePolicy{
				{
					Path:           "/test",
					Methods:        []string{"GET"},
					AllowAnonymous: true,
				},
				{
					Path:           "/test",
					Methods:        []string{"POST", "PUT"},
					AllowAnonymous: false,
				},
			},
			method: "GET",
			want:   true,
		},
		{
			name: "multiple matching policy - same specifity - changes with method",
			matchedPolicies: []models.RoutePolicy{
				{
					Path:           "/test",
					Methods:        []string{"POST", "PUT"},
					AllowAnonymous: false,
				},
				{
					Path:           "/test",
					Methods:        []string{"GET"},
					AllowAnonymous: true,
				},
			},
			method: "GET",
			want:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := services.AuthorizerImpl{}
			if got := a.IsAnonymousAllowed(tt.matchedPolicies, tt.method); got != tt.want {
				t.Errorf("IsAnonymousAllowed() = %v, want %v", got, tt.want)
			}
		})
	}
}
