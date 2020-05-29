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
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "http://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    false,
		},
		{
			name: "no config",
			flags: &flags{
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "http://localhost:8080",
			},
			cfgContent: "",
			wantErr:    true,
		},
		{
			name: "auth server without proxy",
			flags: &flags{
				hmacKey: "SuperSecretKey123!",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    false,
		},
		{
			name: "invalid url scheme",
			flags: &flags{
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "tcp://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "malformed url",
			flags: &flags{
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "!!http://localhost:8080",
			},
			cfgContent: "claimPolicies: {}\nroutePolicies: []",
			wantErr:    true,
		},
		{
			name: "invalid config yaml",
			flags: &flags{
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "http://localhost:8080",
			},
			cfgContent: ": invalid",
			wantErr:    true,
		},
		{
			name: "invalid config content",
			flags: &flags{
				hmacKey:     "SuperSecretKey123!",
				upstreamURL: "http://localhost:8080",
			},
			cfgContent: "claimPolicies:\n PolicyWithoutClaim:\n  - value: test\nroutePolicies: []",
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
