/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetUpdatedElement(t *testing.T) {
	oldE1 := []string{"e1", "e2"}
	newE1 := []string{"e2", "e3"}
	updated1 := getUpdatedElement(oldE1, newE1)
	assert.EqualValues(t, "e1,e2,e3", strings.Join(updated1, SEPARATOR))

	oldE2 := []string{"e1", "e2"}
	newE2 := []string{"e2"}
	updated2 := getUpdatedElement(oldE2, newE2)
	assert.EqualValues(t, "e1,e2", strings.Join(updated2, SEPARATOR))
}

func TestGetRemovedElement(t *testing.T) {
	oriEle := []string{"e1", "e2", "e3"}
	rmvEle := []string{"e2", "e3"}
	result := getRemovedElement(oriEle, rmvEle)
	assert.EqualValues(t, "e1", strings.Join(result, SEPARATOR))

	oriEle = []string{"e1", "e2", "e3", "e4"}
	rmvEle = []string{"e1", "e3"}
	result = getRemovedElement(oriEle, rmvEle)
	assert.EqualValues(t, "e2,e4", strings.Join(result, SEPARATOR))
}

func TestValidateGrant(t *testing.T) {
	for _, p := range []string{
		"/clusters/eks-prod*",
		"/detector/eks-prod/payments*",
		"/detector/eks-prod/payments",
		"/*",
	} {
		assert.NoError(t, ValidateGrant(p), p)
	}
	for _, p := range []string{
		"",
		"*",
		"**",
		"detector/eks-prod*",
		"/detector/eks-prod/payments,*",
		"/detector/eks-prod/payments,",
		"/detector/*/payments",
		"/detector/eks-prod/**",
		"/detector/eks prod*",
		"/detector/eks-prod\n*",
		"/detector/eks-prod\t*",
	} {
		err := ValidateGrant(p)
		assert.ErrorIs(t, err, ErrInvalidGrant, "%q", p)
	}
}

func TestAddPathRejectsInvalidGrantBeforeStore(t *testing.T) {
	// The etcd client is not initialised in tests: reaching the store would panic.
	err := AddPath("payments-team", []string{"/clusters/eks-prod*", "/detector/eks-prod/payments,*"})
	assert.ErrorIs(t, err, ErrInvalidGrant)
	err = AddPath("payments-team", []string{"*"})
	assert.ErrorIs(t, err, ErrInvalidGrant)
}

func TestAddGroupRejectsCommaInClusterOrNamespace(t *testing.T) {
	assert.ErrorIs(t, AddGroup("eks-prod", "payments,", []string{"payments-team"}), ErrInvalidGrant)
	assert.ErrorIs(t, AddGroup("eks-prod,", "x", []string{"payments-team"}), ErrInvalidGrant)
}

func TestGetPathProducesValidGrants(t *testing.T) {
	for _, p := range getPath("eks-prod", "payments") {
		assert.NoError(t, ValidateGrant(p), p)
	}
}
