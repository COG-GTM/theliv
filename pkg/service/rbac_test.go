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

func TestValidateGrantPath(t *testing.T) {
	valid := []string{
		"/clusters/my-cluster*",
		"/detector/my-cluster/default*",
		"/rbac/team-a-role/addpath",
		"/rbac/team-a-role/*",
		"/clusters/prod_cluster/ns-1",
	}
	for _, p := range valid {
		assert.NoError(t, ValidateGrantPath(p), p)
	}
	invalid := []string{
		"", "*", "/*", "**", "/", "/rbac**", "rbac/x", "/rbac/*/addpath",
		"/a,*", "/clusters/a,/rbac*", "/a b", "/a\nb", "/a\t", " /a",
		"/a/../rbac", "/a/./b", "/a//b", "/a%2Fb", "/" + strings.Repeat("a", 512),
	}
	for _, p := range invalid {
		err := ValidateGrantPath(p)
		assert.ErrorIs(t, err, ErrInvalidGrantPath, p)
		assert.True(t, IsInvalidInput(err), p)
	}
}

func TestValidateRoleName(t *testing.T) {
	for _, n := range []string{"team-a-role", "admin", "Team A Admins", "grp_1.x@corp"} {
		assert.NoError(t, ValidateRoleName(n), n)
	}
	invalid := []string{
		"", " ", " team", "team ", ".", "..", "a,b", "a/b", `a\b`, "a*", "a%2Fb",
		"a\nb", "a\x00", strings.Repeat("r", 257),
	}
	for _, n := range invalid {
		err := ValidateRoleName(n)
		assert.ErrorIs(t, err, ErrInvalidRoleName, n)
		assert.True(t, IsInvalidInput(err), n)
	}
}

// Invalid input must be rejected before the role store is touched.
func TestAddPathRejectsInvalidInput(t *testing.T) {
	assert.ErrorIs(t, AddPath("team-a-role", []string{"*"}), ErrInvalidGrantPath)
	assert.ErrorIs(t, AddPath("team-a-role", []string{"/clusters/a*", "/x,*"}), ErrInvalidGrantPath)
	assert.ErrorIs(t, AddPath("a,admin", []string{"/clusters/a*"}), ErrInvalidRoleName)
	assert.ErrorIs(t, AddGroup("a,*", "ns", []string{"team"}), ErrInvalidGrantPath)
	assert.ErrorIs(t, AddGroup("c1", "ns", []string{"team", "bad,role"}), ErrInvalidRoleName)
}
