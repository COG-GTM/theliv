/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGrantCovers(t *testing.T) {
	tests := []struct {
		name      string
		grants    []string
		requested string
		want      bool
	}{
		{"global admin grants anything", []string{"*"}, "/rbac/*", true},
		{"global admin grants exact", []string{"*"}, "/clusters/c1*", true},
		{"exact grant delegates itself", []string{"/rbac/team-a-role/addpath"}, "/rbac/team-a-role/addpath", true},
		{"exact grant cannot delegate wildcard", []string{"/rbac/team-a-role/addpath"}, "/rbac/team-a-role/addpath*", false},
		{"exact grant cannot delegate global", []string{"/rbac/team-a-role/addpath"}, "*", false},
		{"exact grant cannot delegate rbac", []string{"/rbac/team-a-role/addpath"}, "/rbac*", false},
		{"exact grant cannot delegate rbac subtree", []string{"/rbac/team-a-role/addpath"}, "/rbac/*", false},
		{"exact grant cannot delegate register", []string{"/rbac/team-a-role/addpath"}, "/register*", false},
		{"prefix grant delegates narrower", []string{"/clusters/c1*"}, "/clusters/c1/ns*", true},
		{"prefix grant delegates same", []string{"/clusters/c1*"}, "/clusters/c1*", true},
		{"prefix grant delegates exact below", []string{"/clusters*"}, "/clusters/c1", true},
		{"prefix grant cannot delegate broader", []string{"/clusters/c1*"}, "/clusters*", false},
		{"prefix grant cannot delegate sibling", []string{"/clusters/c1*"}, "/detector/c1*", false},
		{"any of several grants", []string{"", "/detector/c1/ns*", "/clusters/c1*"}, "/clusters/c1*", true},
		{"no grants", nil, "/clusters/c1*", false},
		{"empty grant ignored", []string{""}, "/clusters/c1*", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, GrantCovers(tt.grants, tt.requested))
		})
	}
}

// GrantCovers must never allow delegating a pattern that matches a path the
// delegator itself cannot reach.
func TestGrantCoversConsistentWithKeyMatch(t *testing.T) {
	grants := []string{"/clusters/c1*", "/rbac/team-a-role/addpath"}
	requested := []string{"/clusters/c1/ns*", "/clusters/c1*", "/rbac/team-a-role/addpath"}
	probes := []string{"/clusters/c1", "/clusters/c1/ns/x", "/clusters/c10", "/rbac/team-a-role/addpath"}
	for _, req := range requested {
		assert.True(t, GrantCovers(grants, req), req)
		for _, probe := range probes {
			if KeyMatch(probe, req) {
				ok, err := checkPattern(grants, []string{probe})
				assert.NoError(t, err)
				assert.True(t, ok, fmt.Sprintf("%s granted via %s", probe, req))
			}
		}
	}
}

func TestGrantedPathsRequiresAuthenticatedRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/theliv-api/v1/rbac/team-a-role/addpath", nil)
	grants, err := GrantedPaths(r)
	assert.Error(t, err)
	assert.Nil(t, grants)
}
