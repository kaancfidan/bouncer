package models

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

// Config is the overall struct that matches the YAML structure
type Config struct {
	ClaimPolicies map[string][]ClaimRequirement `yaml:"claimPolicies"`
	RoutePolicies []RoutePolicy                 `yaml:"routePolicies"`
}
