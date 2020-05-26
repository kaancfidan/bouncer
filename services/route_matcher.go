package services

import (
	"strings"

	"github.com/gobwas/glob"

	"github.com/kaancfidan/bouncer/models"
)

// RouteMatcher matches given path and method to configured route policies
type RouteMatcher interface {
	MatchRoutePolicies(path string, method string) ([]models.RoutePolicy, error)
}

// RouteMatcherImpl implements glob-based route matching
type RouteMatcherImpl struct {
	routePolicies []models.RoutePolicy
}

// NewRouteMatcher creates a new RouteMatcherImpl instance
func NewRouteMatcher(routePolicies []models.RoutePolicy) *RouteMatcherImpl {
	return &RouteMatcherImpl{routePolicies: routePolicies}
}

// MatchRoutePolicies matches given the request path-method pair to configured routes
// Paths are matched using standard wildcard globs
// If no method is specified in the configuration, that route matches to all methods
func (g RouteMatcherImpl) MatchRoutePolicies(path string, method string) ([]models.RoutePolicy, error) {
	matches := make([]models.RoutePolicy, 0)
	for _, rp := range g.routePolicies {
		normalizedPath := "/" + strings.Trim(path, " \t\n/") + "/"
		normalizedPolicyPath := "/" + strings.Trim(rp.Path, " \t\n/") + "/"

		g, err := glob.Compile(normalizedPolicyPath, '/')
		if err != nil {
			return nil, err
		}

		// check if route matches
		if !g.Match(normalizedPath) {
			continue
		}

		// check if method matches
		// all methods match if no method specified
		if rp.Methods == nil {
			matches = append(matches, rp)
			continue
		}

		for _, m := range rp.Methods {
			if m == method {
				matches = append(matches, rp)
				break
			}
		}
	}

	return matches, nil
}
