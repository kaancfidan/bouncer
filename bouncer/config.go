package bouncer

import "github.com/go-yaml/yaml"

type ClaimPolicy struct {
	Claim string
	Value string
}

type RoutePolicy struct {
	Path           string
	Methods        []string
	PolicyName     string
	AllowAnonymous bool
}

type Config struct {
	ClaimPolicies map[string][]ClaimPolicy
	RoutePolicies []RoutePolicy
}

func ParseConfig(data []byte) (*Config, error) {
	cfg := Config{}

	err := yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
