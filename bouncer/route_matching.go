package bouncer

import "github.com/gobwas/glob"

// RouteMatcher matches given path and method to configured route policies
type RouteMatcher interface {
	MatchRoutePolicies(path string, method string) ([]RoutePolicy, error)
}

// RouteMatcherImpl implements glob-based route matching
type RouteMatcherImpl struct {
	routePolicies []RoutePolicy
}

// NewRouteMatcher creates a new RouteMatcherImpl instance
func NewRouteMatcher(routePolicies []RoutePolicy) *RouteMatcherImpl {
	return &RouteMatcherImpl{routePolicies: routePolicies}
}

// MatchRoutePolicies matches given the request path-method pair to configured routes
// Paths are matched using standard wildcard globs
// If no method is specified in the configuration, that route matches to all methods
func (g RouteMatcherImpl) MatchRoutePolicies(path string, method string) ([]RoutePolicy, error) {
	matches := make([]RoutePolicy, 0)
	for _, rp := range g.routePolicies {
		g, err := glob.Compile(rp.Path, '/')
		if err != nil {
			return nil, err
		}

		// check if route matches
		if !g.Match(path) {
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
