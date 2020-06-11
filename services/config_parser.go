package services

import (
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/go-yaml/yaml"

	"github.com/kaancfidan/bouncer/models"
)

// ConfigParser is the config parsing interface
type ConfigParser interface {
	ParseConfig(reader io.Reader) (*models.Config, error)
}

// YamlConfigParser is the YAML deserialization implementation of ConfigParser
type YamlConfigParser struct{}

// ParseConfig implements config parsing from YAML files
func (YamlConfigParser) ParseConfig(reader io.Reader) (*models.Config, error) {
	decoder := yaml.NewDecoder(reader)

	cfg := models.Config{}
	err := decoder.Decode(&cfg)
	if err != nil {
		return nil, fmt.Errorf("could not parse config yaml: %v", err)
	}

	// parse upstream URL
	if cfg.Server.UpstreamURL != "" {
		cfg.Server.ParsedURL, err = url.Parse(cfg.Server.UpstreamURL)
		if err != nil {
			return nil, fmt.Errorf("upstream url could not be parsed: %w", err)
		}
	}

	// sort route specifications with decreasing specifity
	// this order is used to decide if anonymous requests should be allowed
	sort.SliceStable(cfg.RoutePolicies, func(i, j int) bool {
		p1 := strings.Trim(cfg.RoutePolicies[i].Path, "/ \t\n")
		p2 := strings.Trim(cfg.RoutePolicies[j].Path, "/ \t\n")

		pl1 := strings.Count(p1, "/")
		pl2 := strings.Count(p2, "/")

		// sort by increasing path lengths
		if pl1 > pl2 {
			return true
		} else if pl1 == pl2 {
			wc1 := strings.Count(p1, "*")
			wc2 := strings.Count(p2, "*")

			if wc1 < wc2 { // then by decreasing number of wildcards
				return true
			}
		}
		return false
	})

	return &cfg, nil
}

// ValidateConfig validates a parsed Config struct against following constraints:
//
// - Both claim policies and route policies must not be nil. Empty map/slices are allowed.
//
// - All ClaimRequirement instances must have a claim named.
//
// - All RoutePolicy instances must have a path configured.
//
// - If a RoutePolicy is flagged with AllowAnonymous, it cannot name any claim policies
//
// - If a RoutePolicy has a claim policy named, that claim policy should be defined in the ClaimPolicies section.
func ValidateConfig(cfg *models.Config) error {
	err := validateOperation(cfg.Server)
	if err != nil {
		return fmt.Errorf("invalid operation section: %w", err)
	}

	err = validateClaimPolicies(cfg.ClaimPolicies)
	if err != nil {
		return fmt.Errorf("invalid claimPolicies section: %w", err)
	}

	err = validateRoutePolicies(cfg.ClaimPolicies, cfg.RoutePolicies)
	if err != nil {
		return fmt.Errorf("invalid claimPolicies section: %w", err)
	}

	return nil
}

func validateOperation(cfg models.ServerConfig) error {
	if cfg.ParsedURL != nil && cfg.ParsedURL.Scheme != "http" && cfg.ParsedURL.Scheme != "https" {
		return fmt.Errorf("upstream url scheme must be http or https")
	}

	return nil
}

func validateClaimPolicies(cfg models.ClaimPolicyConfig) error {
	if cfg == nil {
		return fmt.Errorf("claim policies nil")
	}

	for policyName, policy := range cfg {
		for _, requirement := range policy {
			// Claim field is mandatory
			if requirement.Claim == "" {
				return fmt.Errorf("found claim policy (%s) with unnamed claim requirement: %v",
					policyName, policy)
			}
		}
	}

	return nil
}

func validateRoutePolicies(claimPolicies models.ClaimPolicyConfig, routePolicies models.RoutePolicyConfig) error {
	if routePolicies == nil {
		return fmt.Errorf("route policies nil")
	}

	// find existing claim policy names
	existingPolicies := make(map[string]bool)
	for k := range claimPolicies {
		existingPolicies[k] = true
	}

	// check route policies
	for _, p := range routePolicies {
		if p.Path == "" {
			return fmt.Errorf("found route policy without a path denition: %v", p)
		}

		// anonymous routes cannot name claim policies
		if p.AllowAnonymous && (p.PolicyName != "") {
			return fmt.Errorf("found route policy with ambiguous claim policy config: %v", p)
		}

		// non-existing policy check (~foreign key constraint)
		if p.PolicyName != "" && !existingPolicies[p.PolicyName] {
			return fmt.Errorf("non-existing policy name found in route policy: %v", p)
		}
	}

	return nil
}
