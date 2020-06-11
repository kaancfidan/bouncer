package models

import "net/url"

// AuthenticationConfig holds JWT validation related parameters
type AuthenticationConfig struct {
	Issuer             string `yaml:"issuer"`
	Audience           string `yaml:"audience"`
	IgnoreExpiration   bool   `yaml:"ignoreExpiration"`
	IgnoreNotBefore    bool   `yaml:"ignoreNotBefore"`
	ClockSkewInSeconds int    `yaml:"clockSkewInSeconds"`
}

// OriginalRequestHeaders contains headers to lookup for original request method and path details
// in the case where the auth request is a sub-request with distinct method and path
type OriginalRequestHeaders struct {
	Method string `yaml:"method"`
	Path   string `yaml:"path"`
}

// ServerConfig holds operation mode (auth server / reverse proxy) related parameters
type ServerConfig struct {
	OriginalRequestHeaders *OriginalRequestHeaders `yaml:"originalRequestHeaders"`
	UpstreamURL            string                  `yaml:"upstreamUrl"`
	ParsedURL              *url.URL                `yaml:"-"`
}

// ClaimRequirement is a key-value pair for a given claim constraint.
// When multiple claim values are provided, these values are effectively ORed.
type ClaimRequirement struct {
	Claim  string   `yaml:"claim"`
	Values []string `yaml:"values"`
}

// RoutePolicy matches a given path-method pair to a authorization policy
type RoutePolicy struct {
	Path           string   `yaml:"path"`
	Methods        []string `yaml:"methods"`
	PolicyName     string   `yaml:"policyName"`
	AllowAnonymous bool     `yaml:"allowAnonymous"`
}

// ClaimPolicyConfig is a type alias for claimPolicies section
type ClaimPolicyConfig map[string][]ClaimRequirement

// RoutePolicyConfig is a type alias for routePolicies section
type RoutePolicyConfig []RoutePolicy

// Config is the overall struct that matches the YAML structure
type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Authentication AuthenticationConfig `yaml:"authentication"`
	ClaimPolicies  ClaimPolicyConfig    `yaml:"claimPolicies"`
	RoutePolicies  RoutePolicyConfig    `yaml:"routePolicies"`
}
