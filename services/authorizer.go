package services

import (
	"fmt"
	"strings"

	"github.com/kaancfidan/bouncer/models"
)

// Authorizer is the claims-based authorization interface
type Authorizer interface {
	Authorize(policyNames []string, claims map[string]interface{}) (failedPolicy string, err error)
	IsAnonymousAllowed(matchedPolicies []models.RoutePolicy, method string) bool
}

// AuthorizerImpl implements claims base authorization
type AuthorizerImpl struct {
	claimPolicies map[string][]models.ClaimRequirement
}

// NewAuthorizer creates a new AuthorizerImpl instance
func NewAuthorizer(claimPolicies map[string][]models.ClaimRequirement) *AuthorizerImpl {
	return &AuthorizerImpl{claimPolicies: claimPolicies}
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

// IsAnonymousAllowed allows anonymous requests if the most specific route that matches the request has AllowAnonymous
// set to true.
//
// This function expects the matchedPolicies to be sorted by decreasing path length and wildcard specificity.
//
// If more than one route with the same path and wildcard specifity matches the request, first one that also matches
// the method decides if allowed anonymously.
//
// If no route policy is matched to the request, the default behavior is to authenticate.
func (a AuthorizerImpl) IsAnonymousAllowed(matchedPolicies []models.RoutePolicy, method string) bool {
	if len(matchedPolicies) == 0 {
		return false
	}

	mostSpecificPolicy := matchedPolicies[0]

	for i := 1; i < len(matchedPolicies); i++ {
		found := false
		for _, policyMethod := range mostSpecificPolicy.Methods {
			if policyMethod == method {
				found = true
				break
			}
		}

		if found {
			break
		}

		normalizedPath := "/" + strings.Trim(matchedPolicies[i].Path, " \t\n/") + "/"
		normalizedWinnerPath := "/" + strings.Trim(mostSpecificPolicy.Path, " \t\n/") + "/"

		if normalizedPath == normalizedWinnerPath {
			mostSpecificPolicy = matchedPolicies[i]
		}
	}

	return mostSpecificPolicy.AllowAnonymous
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

func claimEquals(claim interface{}, expectation string) bool {
	return fmt.Sprintf("%v", claim) == expectation
}
