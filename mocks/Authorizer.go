// Code generated by mockery v1.0.0. DO NOT EDIT.

package mocks

import bouncer "github.com/kaancfidan/jwt-bouncer/bouncer"
import mock "github.com/stretchr/testify/mock"

// Authorizer is an autogenerated mock type for the Authorizer type
type Authorizer struct {
	mock.Mock
}

// Authorize provides a mock function with given fields: policyNames, claims
func (_m *Authorizer) Authorize(policyNames []string, claims map[string]interface{}) (string, error) {
	ret := _m.Called(policyNames, claims)

	var r0 string
	if rf, ok := ret.Get(0).(func([]string, map[string]interface{}) string); ok {
		r0 = rf(policyNames, claims)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string, map[string]interface{}) error); ok {
		r1 = rf(policyNames, claims)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsAnonymousAllowed provides a mock function with given fields: matchedPolicies
func (_m *Authorizer) IsAnonymousAllowed(matchedPolicies []bouncer.RoutePolicy) bool {
	ret := _m.Called(matchedPolicies)

	var r0 bool
	if rf, ok := ret.Get(0).(func([]bouncer.RoutePolicy) bool); ok {
		r0 = rf(matchedPolicies)
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}
