/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKeyMatch(t *testing.T) {
	tests := []struct {
		key     string
		pattern string
		want    bool
	}{
		{"/detector/eks-prod/payments/events", "/detector/eks-prod/payments*", true},
		{"/detector/eks-prod/payments", "/detector/eks-prod/payments*", true},
		{"/detector/eks-prod/pay", "/detector/eks-prod/payments*", false},
		{"/clusters", "/clusters", true},
		{"/clusters/x", "/clusters", false},
		{"/rbac/admin/addpath", "/*", true},

		// A bare or leading "*" has an empty prefix and must not match everything.
		{"/rbac/admin/addpath", "*", false},
		{"/register/eks-prod", "*", false},
		{"", "*", false},
		{"/register/eks-prod", "**", false},

		// "*" is only a wildcard as the final character.
		{"/detector/eks-prod/payments", "/detector/*/payments", false},
		{"/detector/eks-prod/payments", "/detector/eks-prod/*/x", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, KeyMatch(tt.key, tt.pattern), "KeyMatch(%q, %q)", tt.key, tt.pattern)
	}
}

// A role value that was poisoned before the fix ("...payments,*") must not
// grant access to unrelated APIs once split back into grants.
func TestInjectedWildcardGrantMatchesNothing(t *testing.T) {
	grants := strings.Split("/clusters/eks-prod*,/detector/eks-prod/payments,*", ",")
	for _, path := range []string{"/rbac/payments-team/addpath", "/register/eks-prod", "/detector/eks-dev/billing"} {
		matched, err := checkPattern(grants, []string{path})
		assert.NoError(t, err)
		assert.False(t, matched, path)
	}
	matched, err := checkPattern(grants, []string{"/detector/eks-prod/payments"})
	assert.NoError(t, err)
	assert.True(t, matched)
}
