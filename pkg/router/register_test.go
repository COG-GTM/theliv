/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	log "github.com/fidelity/theliv/pkg/log"
	"github.com/fidelity/theliv/pkg/service"
	"github.com/go-chi/chi/v5"
)

func TestValidateClusterName(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantError bool
	}{
		// Valid names
		{"valid lowercase", "my-cluster", false},
		{"valid short", "abc", false},
		{"valid with numbers", "cluster123", false},
		{"valid hyphenated", "my-prod-cluster", false},
		{"valid with underscores", "my_cluster", false},
		{"valid mixed", "my-prod_cluster", false},
		{"valid max length", "a12345678901234567890123456789012345678901234567890123456789012", false},

		// Invalid - too short
		{"too short", "ab", true},

		// Invalid - too long
		{"too long", "a123456789012345678901234567890123456789012345678901234567890123", true},

		// Invalid - path traversal
		{"path traversal dots", "abc../prod", true},
		{"path traversal double dots", "abc..prod", true},
		{"path traversal slash", "abc/prod", true},
		{"path traversal backslash", "abc\\prod", true},
		{"path traversal relative", "../etc/passwd", true},

		// Invalid - format violations
		{"uppercase", "MyCluster", true},
		{"starts with hyphen", "-cluster", true},
		{"ends with hyphen", "cluster-", true},
		{"starts with underscore", "_cluster", true},
		{"ends with underscore", "cluster_", true},
		{"special chars", "cluster@name", true},
		{"spaces", "my cluster", true},
		{"dots", "cluster.name", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClusterName(tt.input)
			if (err != nil) != tt.wantError {
				t.Errorf("validateClusterName(%q) error = %v, wantError %v", tt.input, err, tt.wantError)
			}
		})
	}
}

func TestValidateClusterURL(t *testing.T) {
	allowed := []string{"eks.amazonaws.com", ".azmk8s.io"}
	tests := []struct {
		name      string
		url       string
		allowed   []string
		wantError bool
	}{
		{"https no allow list", "https://10.0.0.1:6443", nil, false},
		{"http rejected", "http://abc.eks.amazonaws.com", nil, true},
		{"no scheme rejected", "abc.eks.amazonaws.com", nil, true},
		{"file scheme rejected", "file:///etc/passwd", nil, true},
		{"userinfo rejected", "https://u:p@abc.eks.amazonaws.com", nil, true},
		{"query rejected", "https://abc.eks.amazonaws.com?x=1", nil, true},
		{"allowed suffix", "https://ABC.gr7.us-east-1.eks.amazonaws.com", allowed, false},
		{"allowed with port", "https://abc.hcp.eastus.azmk8s.io:443", allowed, false},
		{"exact allowed host", "https://eks.amazonaws.com", allowed, false},
		{"fqdn trailing dot", "https://api.eks.amazonaws.com./", allowed, false},
		{"lookalike rejected", "https://evil-eks.amazonaws.com.attacker.io", allowed, true},
		{"suffix without dot rejected", "https://attackereks.amazonaws.com", allowed, true},
		{"internal host rejected", "https://169.254.169.254", allowed, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClusterURL(tt.url, tt.allowed)
			if (err != nil) != tt.wantError {
				t.Errorf("validateClusterURL(%q) error = %v, wantError %v", tt.url, err, tt.wantError)
			}
		})
	}
}

func TestValidateClusterFields(t *testing.T) {
	ok := service.ClusterBasic{Url: "https://abc.eks.amazonaws.com", CA: "Y2E=", Token: "eyJhbGciOi.eyJpc3Mi.sig-_x", Account: "123456789012", Region: "us-east-1"}
	if err := validateClusterFields(ok); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, tok := range []string{"abc:def", "~abc", "abc~", "x"} {
		if err := validateClusterFields(service.ClusterBasic{Token: tok}); err != nil {
			t.Fatalf("token %q should be accepted, got %v", tok, err)
		}
	}
	if err := validateClusterFields(service.ClusterBasic{}); err != nil {
		t.Fatalf("empty fields should only be logged, got %v", err)
	}
	bad := []service.ClusterBasic{
		{Url: "https://abc.eks.amazonaws.com", Token: "tok\n    server: https://evil"},
		{Url: "https://abc.eks.amazonaws.com", CA: "Y2E=\nusers:"},
		{Url: "https://abc.eks.amazonaws.com", Account: `1", "role": "x`},
		{Url: "https://abc.eks.amazonaws.com", Token: "!foo"},
		{Url: "https://abc.eks.amazonaws.com", Token: "abc:"},
		{Url: "https://abc.eks.amazonaws.com", Token: ":abc"},
		{Url: "https://abc.eks.amazonaws.com", Token: "~"},
		{Url: "https://abc.eks.amazonaws.com", CA: "Y2E=:x"},
		{Url: "https://abc.eks.amazonaws.com", Account: "123456789012", Region: `x", "role": "y`},
		{Url: "http://abc.eks.amazonaws.com"},
	}
	for i, b := range bad {
		if err := validateClusterFields(b); err == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

// Second principal re-registering an existing cluster gets 409 and the stored
// registration is untouched.
func TestClusterRegisterConflictFromSecondPrincipal(t *testing.T) {
	stored := map[string]string{}
	origReg, origP, origG := registerCluster, callerPrincipal, callerCanReplace
	t.Cleanup(func() { registerCluster, callerPrincipal, callerCanReplace = origReg, origP, origG })

	registerCluster = func(_ context.Context, _ *log.SugaredSlogLogger, b service.ClusterBasic, principal string, override bool) error {
		if owner, ok := stored["owner"]; ok && owner != principal && !override {
			return service.ErrClusterExists
		}
		if _, ok := stored["owner"]; !ok {
			stored["owner"] = principal
		}
		stored["url"] = b.Url
		return nil
	}
	callerCanReplace = func(*http.Request, string) (bool, error) { return false, nil }

	r := chi.NewRouter()
	r.Route("/register", Register)
	post := func(principal, url string) int {
		callerPrincipal = func(*http.Request) (string, error) { return principal, nil }
		body := `{"Url":"` + url + `","CA":"Y2E=","Token":"tok"}`
		req := httptest.NewRequest(http.MethodPost, "/register/eks-payments", strings.NewReader(body))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := post("alice", "https://alice.eks.amazonaws.com"); code != http.StatusOK {
		t.Fatalf("first registration: got %d", code)
	}
	if code := post("mallory", "https://attacker.example.com"); code != http.StatusConflict {
		t.Fatalf("second principal: got %d, want 409", code)
	}
	if stored["url"] != "https://alice.eks.amazonaws.com" || stored["owner"] != "alice" {
		t.Fatalf("stored registration changed: %v", stored)
	}
	if code := post("alice", "https://alice2.eks.amazonaws.com"); code != http.StatusOK {
		t.Fatalf("owner update: got %d", code)
	}
	if code := post("mallory", "http://attacker.example.com"); code != http.StatusBadRequest {
		t.Fatalf("non-https URL: got %d, want 400", code)
	}

	callerPrincipal = func(*http.Request) (string, error) { return "", service.ErrNoPrincipal }
	req := httptest.NewRequest(http.MethodPost, "/register/eks-payments", strings.NewReader(`{"Url":"https://a.eks.amazonaws.com"}`))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unknown principal: got %d, want 403", rec.Code)
	}
}
