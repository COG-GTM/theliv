/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	tests := []struct {
		name      string
		input     string
		allowed   []string
		wantError bool
	}{
		// Valid
		{"eks endpoint", "https://ABCDEF0123456789.gr7.us-east-1.eks.amazonaws.com", nil, false},
		{"with port", "https://api.prod.example.com:6443", nil, false},
		{"numeric labels not an ip", "https://k8s.1.2.example.com", nil, false},
		{"trailing slash", "https://api.prod.example.com/", nil, false},
		{"trailing dot", "https://api.prod.example.com.", nil, false},
		{"allowlisted subdomain", "https://abc.gr7.us-east-1.eks.amazonaws.com", []string{"eks.amazonaws.com"}, false},
		{"allowlisted wildcard", "https://abc.eks.amazonaws.com", []string{"*.eks.amazonaws.com"}, false},
		{"allowlisted exact", "https://k8s.example.com", []string{"other.org", "K8S.example.com"}, false},

		// Missing / malformed
		{"empty", "", nil, true},
		{"no scheme", "api.prod.example.com", nil, true},
		{"http", "http://api.prod.example.com", nil, true},
		{"file scheme", "file:///etc/passwd", nil, true},
		{"userinfo", "https://user:pass@api.prod.example.com", nil, true},
		{"path", "https://api.prod.example.com/foo", nil, true},
		{"query", "https://api.prod.example.com?x=1", nil, true},
		{"fragment", "https://api.prod.example.com#x", nil, true},
		{"newline injection", "https://api.prod.example.com\n    insecure-skip-tls-verify: true", nil, true},
		{"port zero", "https://api.prod.example.com:0", nil, true},
		{"port too large", "https://api.prod.example.com:70000", nil, true},
		{"underscore host", "https://api_prod.example.com", nil, true},

		// Internal targets
		{"ipv4 loopback", "https://127.0.0.1:1", nil, true},
		{"ipv4 private", "https://10.0.3.7:8443", nil, true},
		{"ipv4 metadata", "https://169.254.169.254", nil, true},
		{"ipv6 loopback", "https://[::1]:443", nil, true},
		{"ipv6 mapped", "https://[::ffff:10.0.3.7]", nil, true},
		{"decimal ip", "https://2130706433", nil, true},
		{"hex ip", "https://0x7f.0x0.0x0.0x1", nil, true},
		{"short ip", "https://127.1", nil, true},
		{"localhost", "https://localhost:8443", nil, true},
		{"localhost subdomain", "https://foo.localhost", nil, true},
		{"single label", "https://kubernetes", nil, true},
		{"kubernetes service", "https://kubernetes.default.svc", nil, true},
		{"kubernetes service fqdn", "https://kubernetes.default.svc.cluster.local", nil, true},
		{"ec2 internal", "https://ip-10-0-3-7.ec2.internal", nil, true},
		{"mdns local", "https://printer.local", nil, true},
		{"reverse dns", "https://7.3.0.10.in-addr.arpa", nil, true},
		{"nip.io", "https://10.0.3.7.nip.io", nil, true},
		{"sslip.io prefixed", "https://app.169.254.169.254.sslip.io", nil, true},
		{"sslip.io dashed", "https://10-0-3-7.sslip.io", nil, true},
		{"loopback wildcard dns", "https://api.localtest.me", nil, true},
		{"allowlist does not admit internal", "https://kubernetes.default.svc", []string{"svc"}, true},

		// Allowlist
		{"numeric labels allowlisted", "https://api.1.2.3.4.example.com", []string{"example.com"}, false},
		{"numeric labels", "https://api.1.2.3.4.example.com", nil, false},
		{"not allowlisted", "https://evil.example.com", []string{"eks.amazonaws.com"}, true},
		{"suffix trick", "https://evileks.amazonaws.com", []string{"eks.amazonaws.com"}, true},
		{"allowlist does not admit ip", "https://10.0.3.7", []string{"eks.amazonaws.com"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateClusterURL(tt.input, tt.allowed)
			if (err != nil) != tt.wantError {
				t.Errorf("validateClusterURL(%q, %v) error = %v, wantError %v", tt.input, tt.allowed, err, tt.wantError)
			}
		})
	}
}

func TestClusterRegisterRejectsInvalidURL(t *testing.T) {
	r := chi.NewRouter()
	Register(r)

	for _, u := range []string{"https://127.0.0.1:1", "https://10.0.3.7:8443", "http://api.example.com", ""} {
		body := `{"Url": "` + u + `", "CA": "Y2E=", "Token": "t"}`
		req := httptest.NewRequest(http.MethodPost, "/eks-probe", strings.NewReader(body))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("register with Url %q: status = %d, want %d", u, rec.Code, http.StatusBadRequest)
		}
	}
}
