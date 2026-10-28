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

func TestValidatePaths(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		wantError bool
	}{
		{"exact", "/clusters", false},
		{"prefix wildcard", "/detector/eks-prod/payments*", false},
		{"bare wildcard", "*", true},
		{"empty", "", true},
		{"comma", "/detector/eks-prod/payments,*", true},
		{"trailing comma", "/detector/a,", true},
		{"space", "/detector/a *", true},
		{"newline", "/detector/a\n*", true},
		{"wildcard in middle", "/detector/*/payments", true},
		{"double wildcard", "/detector/**", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePaths([]string{tt.path})
			assert.Equal(t, tt.wantError, err != nil, "err=%v", err)
		})
	}
}

func TestAddPathRejectsInvalidPaths(t *testing.T) {
	assert.ErrorIs(t, AddPath("payments-team", []string{"*"}), ErrInvalidPath)
	assert.ErrorIs(t, AddPath("payments-team", []string{"/detector/eks-prod/payments,*"}), ErrInvalidPath)
}
