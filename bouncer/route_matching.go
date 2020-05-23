package bouncer

import "github.com/gobwas/glob"

// RouteMatcher matches given path and method to configured route policies
type RouteMatcher interface {
	MatchRoutePolicies(path string, method string) ([]RoutePolicy, error)
}

type routeMatcherImpl struct {
	routePolicies []RoutePolicy
}

func NewRouteMatcher(routePolicies []RoutePolicy) *routeMatcherImpl {
	return &routeMatcherImpl{routePolicies: routePolicies}
}

// routeMatcherImpl matches given path configurations with regexp
func (g routeMatcherImpl) MatchRoutePolicies(path string, method string) ([]RoutePolicy, error) {
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
