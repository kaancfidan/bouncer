package services

import (
	"fmt"
	"sort"
	"strings"

	"github.com/kaancfidan/bouncer/models"
)

// Authorizer is the claims-based authorization interface
type Authorizer interface {
	Authorize(policyNames []string, claims map[string]interface{}) (failedPolicy string, err error)
	IsAnonymousAllowed(matchedPolicies []models.RoutePolicy) bool
}

// AuthorizerImpl implements claims base authorization
type AuthorizerImpl struct {
	claimPolicies map[string][]models.ClaimRequirement
}

// NewAuthorizer creates a new AuthorizerImpl instance
func NewAuthorizer(claimPolicies map[string][]models.ClaimRequirement) *AuthorizerImpl {
	return &AuthorizerImpl{claimPolicies: claimPolicies}
}

func (a AuthorizerImpl) getClaimPolicies(policyNames []string) ([]models.ClaimRequirement, error) {
	keys := make(map[string]bool)
	var claimPolicies []models.ClaimRequirement

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
		if cp.Values == nil {
			continue
		}

		// if the matching claim in the token is an array
		// check if the array contains the expected value
		if arr, ok := claim.([]interface{}); ok {
			found := false
			for _, val := range arr {
				for _, cfgVal := range cp.Values {
					if claimEquals(val, cfgVal) {
						found = true
						break
					}
				}

				if found {
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
		found := false
		for _, cfgVal := range cp.Values {
			if claimEquals(claims[cp.Claim], cfgVal) {
				found = true
				break
			}
		}

		if !found {
			failedClaim = cp.Claim
		}
	}

	return failedClaim, nil
}

func claimEquals(claim interface{}, expectation string) bool {
	return fmt.Sprintf("%v", claim) == expectation
}

// IsAnonymousAllowed checks if the most specific policy allows anonymous access
// if no route is matched, default behaviour is to authenticate
func (a AuthorizerImpl) IsAnonymousAllowed(matchedPolicies []models.RoutePolicy) bool {
	// sort with decreasing specifity
	sort.SliceStable(matchedPolicies, func(i, j int) bool {
		p1 := strings.Trim(matchedPolicies[i].Path, "/ \t\n")
		p2 := strings.Trim(matchedPolicies[j].Path, "/ \t\n")

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

	return len(matchedPolicies) > 0 && matchedPolicies[0].AllowAnonymous
}
