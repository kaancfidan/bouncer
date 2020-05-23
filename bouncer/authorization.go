package bouncer

import "fmt"

// Authorizer is the claims-based authorization interface
type Authorizer interface {
	Authorize(policyNames []string, claims map[string]interface{}) (failedPolicy string, err error)
	IsAnonymousAllowed(matchedPolicies []RoutePolicy) bool
}

// AuthorizerImpl implements claims base authorization
type AuthorizerImpl struct {
	claimPolicies map[string][]ClaimPolicy
}

// NewAuthorizer creates a new AuthorizerImpl instance
func NewAuthorizer(claimPolicies map[string][]ClaimPolicy) *AuthorizerImpl {
	return &AuthorizerImpl{claimPolicies: claimPolicies}
}

func (a AuthorizerImpl) getClaimPolicies(policyNames []string) ([]ClaimPolicy, error) {
	keys := make(map[string]bool)
	var claimPolicies []ClaimPolicy

	for _, policyName := range policyNames {
		// policy already added
		if _, value := keys[policyName]; value {
			continue
		}

		policy := a.claimPolicies[policyName]

		if policy == nil {
			return nil, fmt.Errorf("missing policy config: %s", policyName)
		}

		keys[policyName] = true
		claimPolicies = append(claimPolicies, policy...)
	}

	return claimPolicies, nil
}

// Authorize checks claim values and returns the first failed claim
func (a AuthorizerImpl) Authorize(policyNames []string, claims map[string]interface{}) (failedClaim string, err error) {
	claimPolicies, err := a.getClaimPolicies(policyNames)
	if err != nil {
		return "", err
	}

	for _, cp := range claimPolicies {
		claim, exists := claims[cp.Claim]

		if !exists {
			failedClaim = cp.Claim
			break
		}

		// if no value specified, policy passes just by existing
		if cp.Value == "" {
			continue
		}

		// if the matching claim in the token is an array
		// check if the array contains the expected value
		if arr, ok := claim.([]interface{}); ok {
			found := false
			for _, val := range arr {
				if val == cp.Value {
					found = true
					break
				}
			}

			if !found {
				failedClaim = cp.Claim
				break
			}

			continue
		}

		// if the matching claim is not an array, check direct equality with expectation
		if claims[cp.Claim] != cp.Value {
			failedClaim = cp.Claim
			break
		}
	}

	return failedClaim, nil
}

// IsAnonymousAllowed checks if the matched policies all have allow anonymous flags set to true
// if no route is configured, default behaviour is to authenticate
func (a AuthorizerImpl) IsAnonymousAllowed(matchedPolicies []RoutePolicy) bool {
	allowAnon := len(matchedPolicies) > 0
	for _, p := range matchedPolicies {
		if !p.AllowAnonymous {
			allowAnon = false
			break
		}
	}
	return allowAnon
}
