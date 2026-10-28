/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import "testing"

func TestIsWhitelisted(t *testing.T) {
	tests := []struct {
		name      string
		whitelist []string
		path      string
		want      bool
	}{
		{"exact entry matches", []string{"/theliv-api/v1/userinfo"}, "/theliv-api/v1/userinfo", true},
		{"exact entry does not match wildcard request", []string{"/theliv-api/v1/userinfo"}, "/theliv-api/v1/userinfo*anything", false},
		{"exact entry does not match longer path", []string{"/theliv-api/v1/userinfo"}, "/theliv-api/v1/userinfo/extra", false},
		{"wildcard entry matches its prefix", []string{"/theliv-api/v1/configinfo*"}, "/theliv-api/v1/configinfo", true},
		{"wildcard entry matches sub path", []string{"/theliv-api/v1/configinfo*"}, "/theliv-api/v1/configinfo/abc", true},
		{"wildcard entry does not match other path", []string{"/theliv-api/v1/configinfo*"}, "/theliv-api/v1/clusters", false},
		{"trailing slash entry does not match wildcard request", []string{"/theliv-api/v1/clusters/"}, "/theliv-api/v1/clusters/*/namespaces", false},
		{"prefix entry does not match parameterised route", []string{"/theliv-api/v1/clusters"}, "/theliv-api/v1/clusters/c1/namespaces", false},
		{"any entry may match", []string{"/theliv-api/v1/userinfo", "/theliv-api/v1/configinfo*"}, "/theliv-api/v1/configinfo/x", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := isWhitelisted(tt.path, tt.whitelist)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("isWhitelisted(%q, %v) = %v, want %v", tt.path, tt.whitelist, got, tt.want)
			}
		})
	}
}

func TestKeyMatchOnlyHonoursWildcardInPattern(t *testing.T) {
	if KeyMatch("/theliv-api/v1/clusters/*/namespaces", "/theliv-api/v1/clusters/") {
		t.Error("'*' in the key must not act as a wildcard")
	}
	if !KeyMatch("/clusters/c1/namespaces", "/clusters/*") {
		t.Error("'*' in the pattern should match")
	}
}
