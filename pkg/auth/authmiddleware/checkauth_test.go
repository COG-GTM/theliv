/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"net/http/httptest"
	"testing"
)

func TestKeyMatch(t *testing.T) {
	tests := []struct {
		path    string
		pattern string
		want    bool
	}{
		// grants written without a "/" before the "*"
		{"/detector/prod/app/detect", "/detector/prod/app*", true},
		{"/detector/prod/app/event", "/detector/prod/app*", true},
		{"/detector/prod/app", "/detector/prod/app*", true},
		{"/detector/prod/app-secrets/detect", "/detector/prod/app*", false},
		{"/detector/prod/apps/event", "/detector/prod/app*", false},
		{"/clusters/prod/namespaces", "/clusters/prod*", true},
		{"/clusters/prod", "/clusters/prod*", true},
		{"/clusters/prod-dr/namespaces", "/clusters/prod*", false},
		{"/clusters/production/namespaces", "/clusters/prod*", false},
		{"/adgroup/prod/app-secrets", "/adgroup/prod/app*", false},
		{"/adgroup/prod/app,*", "/adgroup/prod/app*", false},
		{"/adgroup/prod/app", "/adgroup/prod/app*", true},

		// grants written with an explicit boundary
		{"/detector/prod/app/detect", "/detector/prod/app/*", true},
		{"/detector/prod/app", "/detector/prod/app/*", true},
		{"/detector/prod/app-secrets/detect", "/detector/prod/app/*", false},
		{"/clusters/prod/namespaces", "/clusters/prod/*", true},
		{"/clusters/prod-dr/namespaces", "/clusters/prod/*", false},

		// global and exact grants
		{"/detector/prod/app/detect", "*", true},
		{"/detector/prod/app/detect", "/*", true},
		{"/userinfo", "/userinfo", true},
		{"/userinfo/x", "/userinfo", false},
		{"/userinfos", "/userinfo", false},
	}
	for _, tt := range tests {
		if got := KeyMatch(tt.path, tt.pattern); got != tt.want {
			t.Errorf("KeyMatch(%q, %q) = %v, want %v", tt.path, tt.pattern, got, tt.want)
		}
	}
}

func TestCheckPattern(t *testing.T) {
	grants := []string{"/clusters/prod*", "/detector/prod/app*"}

	for path, want := range map[string]bool{
		"/detector/prod/app/detect":         true,
		"/clusters/prod/namespaces":         true,
		"/detector/prod/app-secrets/detect": false,
		"/clusters/prod-dr/namespaces":      false,
		"/detector/prod2/app/detect":        false,
	} {
		got, err := checkPattern(grants, []string{path})
		if err != nil {
			t.Fatalf("checkPattern(%q) error: %v", path, err)
		}
		if got != want {
			t.Errorf("checkPattern(grants, %q) = %v, want %v", path, got, want)
		}
	}

	if _, err := checkPattern(nil, []string{"/x"}); err == nil {
		t.Error("checkPattern with no patterns should return an error")
	}
}

func TestRequestPath(t *testing.T) {
	tests := []struct {
		target string
		want   string
		ok     bool
	}{
		{"/theliv-api/v1/detector/prod/app/detect", "/theliv-api/v1/detector/prod/app/detect", true},
		{"/theliv-api/v1/clusters/prod/namespaces/", "/theliv-api/v1/clusters/prod/namespaces", true},
		{"/theliv-api/v1/detector/prod/app/../app-secrets/detect", "", false},
		{"/theliv-api/v1/detector/prod/app/./detect", "", false},
		{"/theliv-api/v1/detector/prod/app/..", "", false},
		{"/theliv-api/v1/detector/prod/app//detect", "", false},
		{"/theliv-api/v1/detector/prod/app%2F..%2Fapp-secrets/detect", "/theliv-api/v1/detector/prod/app%2F..%2Fapp-secrets/detect", true},
		{"/", "", false},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "http://theliv.local"+tt.target, nil)
		got, ok := requestPath(r)
		if got != tt.want || ok != tt.ok {
			t.Errorf("requestPath(%q) = (%q, %v), want (%q, %v)", tt.target, got, ok, tt.want, tt.ok)
		}
	}

	// The escaped form is what gets authorized, so an encoded "/" cannot widen a namespace grant.
	r := httptest.NewRequest("GET", "http://theliv.local/theliv-api/v1/detector/prod/app%2F..%2Fapp-secrets/detect", nil)
	p, _ := requestPath(r)
	if KeyMatch(p[len(URLPrefix):], "/detector/prod/app*") {
		t.Errorf("encoded path %q should not match /detector/prod/app*", p)
	}
}
