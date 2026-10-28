/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateClusterNamespace(t *testing.T) {
	tests := []struct {
		name      string
		cluster   string
		namespace string
		wantError bool
	}{
		{"valid", "eks-prod", "payments", false},
		{"valid underscore cluster", "eks_prod", "payments-api", false},
		{"trailing comma namespace", "eks-prod", "payments,", true},
		{"comma in cluster", "eks-prod,", "x", true},
		{"comma injected grant", "eks-prod", "payments,/rbac", true},
		{"wildcard namespace", "eks-prod", "*", true},
		{"wildcard cluster", "*", "payments", true},
		{"whitespace", "eks-prod", "pay ments", true},
		{"slash", "eks-prod", "a/b", true},
		{"uppercase", "eks-prod", "Payments", true},
		{"empty namespace", "eks-prod", "", true},
		{"empty cluster", "", "payments", true},
		{"underscore namespace", "eks-prod", "pay_ments", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClusterNamespace(tt.cluster, tt.namespace)
			assert.Equal(t, tt.wantError, err != nil, "err=%v", err)
			if tt.wantError {
				assert.True(t, errors.Is(err, ErrInvalidClusterOrNamespace))
			}
		})
	}
}

func TestAddRemoveGroupRejectInvalidNames(t *testing.T) {
	err := AddGroup("eks-prod", "payments,", []string{"payments-team"})
	assert.ErrorIs(t, err, ErrInvalidClusterOrNamespace)
	err = AddGroup("eks-prod,", "x", []string{"payments-team"})
	assert.ErrorIs(t, err, ErrInvalidClusterOrNamespace)
	err = RemoveGroup("eks-prod", "payments,", []string{"payments-team"})
	assert.ErrorIs(t, err, ErrInvalidClusterOrNamespace)
}

func TestGetPathProducesValidGrants(t *testing.T) {
	paths := getPath("eks-prod", "payments")
	assert.Equal(t, []string{"/clusters/eks-prod*", "/detector/eks-prod/payments*"}, paths)
	assert.NoError(t, ValidatePaths(paths))
}
