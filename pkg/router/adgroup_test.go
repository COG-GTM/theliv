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

func TestAdGroupRejectsInvalidClusterOrNamespace(t *testing.T) {
	r := chi.NewRouter()
	r.Route("/adgroup", AdGroup)

	paths := []string{
		"/adgroup/eks-prod/payments,",
		"/adgroup/eks-prod,/x",
		"/adgroup/eks-prod/payments,%2Frbac",
		"/adgroup/eks-prod/*",
		"/adgroup/eks-prod/pay%20ments",
	}
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, p := range paths {
			req := httptest.NewRequest(method, p, strings.NewReader(`{"adgroups": ["payments-team"]}`))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s %s: got status %d, want %d", method, p, w.Code, http.StatusBadRequest)
			}
		}
	}
}
