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

func TestValidAdGroupTarget(t *testing.T) {
	tests := []struct {
		cluster   string
		namespace string
		want      bool
	}{
		{"prod", "app", true},
		{"prod-eu", "app-payments", true},
		{"my_cluster", "kube-system", true},
		{"prod", "*", false},
		{"prod", "app*", false},
		{"prod", "app,*", false},
		{"prod*", "app", false},
		{"prod", "app%2Fx", false},
		{"prod", "..", false},
		{"prod", "App", false},
		{"prod", "", false},
		{"", "app", false},
	}
	for _, tt := range tests {
		if got := validAdGroupTarget(tt.cluster, tt.namespace); got != tt.want {
			t.Errorf("validAdGroupTarget(%q, %q) = %v, want %v", tt.cluster, tt.namespace, got, tt.want)
		}
	}
}

func TestAdGroupRejectsInvalidTarget(t *testing.T) {
	r := chi.NewRouter()
	r.Route("/adgroup", AdGroup)

	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, target := range []string{"/adgroup/prod/app,*", "/adgroup/prod/*", "/adgroup/prod*/app"} {
			req := httptest.NewRequest(method, target, strings.NewReader(`{"adgroups":["team-app"]}`))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s = %d, want 400", method, target, w.Code)
			}
		}
	}
}
