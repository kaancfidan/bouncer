package models

// ClaimPolicy is a key-value pair for a given claim constraint
type ClaimPolicy struct {
	Claim string
	Value string
}

// RoutePolicy matches a given path-method pair to a authorization policy
type RoutePolicy struct {
	Path           string
	Methods        []string
	PolicyName     string
	AllowAnonymous bool
}

// Config is the overall struct that matches the YAML structure
type Config struct {
	ClaimPolicies map[string][]ClaimPolicy
	RoutePolicies []RoutePolicy
}
