package bouncer

import "github.com/go-yaml/yaml"

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

// ParseConfig accepts a YAML file content and returns a parsed Config object
func ParseConfig(data []byte) (*Config, error) {
	cfg := Config{}

	err := yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
