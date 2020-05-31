package main

import (
	"bytes"
	"testing"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name       string
		flags      *flags
		cfgContent string
		wantErr    bool
	}{
		{
			name: "happy path",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    false,
		},
		{
			name: "no config",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
			},
			cfgContent: "",
			wantErr:    true,
		},
		{
			name: "reverse proxy",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
				upstreamURL:   "http://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    false,
		},
		{
			name: "clock skewed",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
				clockSkew:     "10",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    false,
		},
		{
			name: "invalid url scheme",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
				upstreamURL:   "tcp://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "malformed url",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
				upstreamURL:   "!!http://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "invalid config yaml",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
			},
			cfgContent: ": invalid",
			wantErr:    true,
		},
		{
			name: "invalid config content",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
			},
			cfgContent: "claimPolicies:\n PolicyWithoutClaim:\n  - value: test\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "no signing key",
			flags: &flags{
				signingMethod: "HMAC",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "no signing method",
			flags: &flags{
				signingKey: "SuperSecretKey123!",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "invalid clock skew flag",
			flags: &flags{
				signingKey:    "SuperSecretKey123!",
				signingMethod: "HMAC",
				clockSkew:     "not a number",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := bytes.Buffer{}
			buf.WriteString(tt.cfgContent)

			_, err := newServer(tt.flags, &buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("newServer() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
