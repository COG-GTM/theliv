/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"strings"
	"testing"

	auth "github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/stretchr/testify/assert"
)

func TestGetPath(t *testing.T) {
	assert.Equal(t, []string{"/clusters/prod/*", "/detector/prod/app/*"}, getPath("prod", "app"))
}

func TestGetPathGrantsOnlyTheNamedClusterAndNamespace(t *testing.T) {
	grants := getPath("prod", "app")
	matches := func(p string) bool {
		for _, g := range grants {
			if auth.KeyMatch(p, g) {
				return true
			}
		}
		return false
	}

	assert.True(t, matches("/clusters/prod/namespaces"))
	assert.True(t, matches("/detector/prod/app/detect"))
	assert.True(t, matches("/detector/prod/app/event"))

	assert.False(t, matches("/clusters/prod-dr/namespaces"))
	assert.False(t, matches("/detector/prod/app-secrets/detect"))
	assert.False(t, matches("/detector/prod-dr/app/detect"))
	assert.False(t, matches("/detector/prod/other/detect"))
}

func TestRemoveGroupPathsIncludeLegacyGrants(t *testing.T) {
	existing := []string{"/clusters/prod*", "/detector/prod/app*", "/clusters/qa/*", "/detector/qa/app/*"}
	rmv := append(getPath("prod", "app"), getLegacyPath("prod", "app")...)
	assert.Equal(t, "/clusters/qa/*,/detector/qa/app/*", strings.Join(getRemovedElement(existing, rmv), SEPARATOR))
}
