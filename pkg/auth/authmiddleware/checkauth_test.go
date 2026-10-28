/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"testing"
)

func TestKeyMatch(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		grant string
		want  bool
	}{
		{"exact", "/clusters", "/clusters", true},
		{"exact mismatch", "/clusters/a", "/clusters", false},
		{"prefix wildcard", "/detector/eks-prod/payments/pods", "/detector/eks-prod/payments*", true},
		{"prefix wildcard equal", "/detector/eks-prod/payments", "/detector/eks-prod/payments*", true},
		{"prefix wildcard mismatch", "/detector/eks-prod/other", "/detector/eks-prod/payments*", false},
		{"short key", "/detector", "/detector/eks-prod*", false},
		{"bare wildcard", "/rbac/admin/addpath", "*", false},
		{"bare wildcard with spaces", "/register", " * ", false},
		{"wildcard in middle", "/detector/x/payments", "/detector/*/payments", false},
		{"empty grant", "/register", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KeyMatch(tt.key, tt.grant); got != tt.want {
				t.Errorf("KeyMatch(%q, %q) = %v, want %v", tt.key, tt.grant, got, tt.want)
			}
		})
	}
}
