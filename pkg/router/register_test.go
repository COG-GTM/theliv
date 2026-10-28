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

func TestClusterRegisterRejectsKubeconfigInjection(t *testing.T) {
	bodies := map[string]string{
		"token exec":      `{"Url":"https://attacker.example","CA":"","Token":"\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: /bin/sh\n      args: [\"-c\", \"id\"]"}`,
		"token tokenFile": `{"Url":"https://attacker.example","Token":"x\n    tokenFile: /etc/passwd"}`,
		"url newline":     `{"Url":"https://attacker.example\n    insecure-skip-tls-verify: true","Token":"abc"}`,
		"url http":        `{"Url":"http://attacker.example","Token":"abc"}`,
		"ca newline":      `{"Url":"https://attacker.example","CA":"Zm9v\n    proxy-url: http://x","Token":"abc"}`,
		"account":         `{"Url":"https://attacker.example","Token":"abc","Account":"1\", \"role\": \"x"}`,
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			r := chi.NewRouter()
			Register(r)
			req := httptest.NewRequest(http.MethodPost, "/eks-prod", strings.NewReader(body))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400 (body %q)", w.Code, w.Body.String())
			}
		})
	}
}
