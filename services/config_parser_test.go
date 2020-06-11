package services

import (
	"bytes"
	"net/url"
	"reflect"
	"testing"

	"github.com/kaancfidan/bouncer/models"
)

func TestYamlConfigParser_ParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    *models.Config
		wantErr bool
	}{
		{
			name:    "empty config",
			yaml:    "{}",
			want:    &models.Config{},
			wantErr: false,
		},
		{
			name:    "invalid yaml",
			yaml:    ": invalid",
			want:    nil,
			wantErr: true,
		},
		{
			name: "claim policies deserialize",
			yaml: "claimPolicies:\n" +
				" TestPolicy:\n" +
				"  - claim: test\n" +
				"    values: [1,2,3]",
			want: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{
					"TestPolicy": {
						models.ClaimRequirement{
							Claim:  "test",
							Values: []string{"1", "2", "3"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "route policies deserialize",
			yaml: "routePolicies:\n" +
				" - path: /test\n" +
				"   methods: [GET, POST]\n" +
				"   policyName: TestPolicy\n" +
				"   allowAnonymous: true",
			want: &models.Config{
				RoutePolicies: []models.RoutePolicy{
					{Path: "/test", Methods: []string{"GET", "POST"}, PolicyName: "TestPolicy", AllowAnonymous: true},
				},
			},
			wantErr: false,
		},
		{
			name: "server config deserialize",
			yaml: "server:\n" +
				" originalRequestHeaders:\n" +
				"  path: X-test-path\n" +
				"  method: X-test-method\n" +
				" upstreamUrl: http://url/to/upstream",
			want: &models.Config{
				Server: models.ServerConfig{
					OriginalRequestHeaders: &models.OriginalRequestHeaders{
						Method: "X-test-method",
						Path:   "X-test-path",
					},
					UpstreamURL: "http://url/to/upstream",
					ParsedURL: &url.URL{
						Scheme: "http",
						Host:   "url",
						Path:   "/to/upstream",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "upstream url error",
			yaml: "server:\n" +
				" upstreamUrl: ¡http://clearly not a valid url!",
			want:    nil,
			wantErr: true,
		},
		{
			name: "sorts route policies by specifity",
			yaml: "routePolicies:\n" +
				" - path: /**\n" +
				" - path: /test/*/\n" +
				" - path: /test/this\n" +
				" - path: /test/**\n" +
				" - path: /test/this/and/that\n" +
				" - path: /test/**/that\n" +
				" - path: /test",
			want: &models.Config{
				RoutePolicies: []models.RoutePolicy{
					{Path: "/test/this/and/that"},
					{Path: "/test/**/that"},
					{Path: "/test/this"},
					{Path: "/test/*/"},
					{Path: "/test/**"},
					{Path: "/test"},
					{Path: "/**"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := YamlConfigParser{}

			reader := bytes.Buffer{}
			reader.WriteString(tt.yaml)

			got, err := parser.ParseConfig(&reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseConfig() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *models.Config
		wantErr bool
	}{
		{
			name:    "empty config",
			config:  &models.Config{},
			wantErr: false,
		},
		{
			name: "claim requirement without claim",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{
					"Test": {models.ClaimRequirement{}},
				},
				RoutePolicies: []models.RoutePolicy{},
			},
			wantErr: true,
		},
		{
			name: "route policy without path",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{},
				RoutePolicies: []models.RoutePolicy{
					{AllowAnonymous: true},
				},
			},
			wantErr: true,
		},
		{
			name: "route policy both allow anon and policy named",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{
					"TestPolicy": {
						models.ClaimRequirement{Claim: "test"},
					},
				},
				RoutePolicies: []models.RoutePolicy{
					{
						Path:           "/",
						AllowAnonymous: true,
						PolicyName:     "TestPolicy",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "route policy allow anon false but policy not named",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{},
				RoutePolicies: []models.RoutePolicy{
					{
						Path:           "/",
						AllowAnonymous: false,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "route policy names non-existing claim policy",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{},
				RoutePolicies: []models.RoutePolicy{
					{
						Path:       "/",
						PolicyName: "NonExistingClaimPolicy",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid allow anon",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{},
				RoutePolicies: []models.RoutePolicy{
					{
						Path:           "/",
						AllowAnonymous: true,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "valid route with policy",
			config: &models.Config{
				ClaimPolicies: map[string][]models.ClaimRequirement{
					"TestPolicy": {models.ClaimRequirement{Claim: "test"}},
				},
				RoutePolicies: []models.RoutePolicy{
					{
						Path:       "/",
						PolicyName: "TestPolicy",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid url scheme",
			config: &models.Config{
				Server: models.ServerConfig{
					UpstreamURL: "tcp://not/a/valid/scheme",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if tt.config.Server.UpstreamURL != "" {
				var err error
				tt.config.Server.ParsedURL, err = url.Parse(tt.config.Server.UpstreamURL)
				if err != nil {
					t.Errorf("could not parse url")
					return
				}
			}

			if err := ValidateConfig(tt.config); (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
