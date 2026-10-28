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
	"github.com/stretchr/testify/assert"
)

func TestAdGroupRejectsInvalidClusterOrNamespace(t *testing.T) {
	r := chi.NewRouter()
	r.Route("/adgroup", AdGroup)

	paths := []string{
		"/adgroup/eks-prod/payments,",
		"/adgroup/eks-prod/payments,*",
		"/adgroup/eks-prod,/x",
		"/adgroup/eks-prod/payments%2C",
		"/adgroup/eks-prod/*",
		"/adgroup/eks-prod/pay*",
		"/adgroup/*/payments",
		"/adgroup/eks-prod/Payments",
		"/adgroup/eks-prod/payments.team",
		"/adgroup/eks-prod/-payments",
		"/adgroup/ek/payments",
	}
	// The etcd client is not initialised in tests, so any request that got past
	// validation would panic instead of returning 400.
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, p := range paths {
			req := httptest.NewRequest(method, p, strings.NewReader(`{"adgroups": ["payments-team"]}`))
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)
			assert.Equal(t, http.StatusBadRequest, rec.Code, "%s %s", method, p)
		}
	}
}

func TestValidateClusterNamespace(t *testing.T) {
	assert.NoError(t, validateClusterNamespace("eks-prod", "payments"))
	assert.NoError(t, validateClusterNamespace("eks_prod", "kube-system"))
	assert.NoError(t, validateClusterNamespace("eks-prod", "a"))
	assert.NoError(t, validateClusterNamespace("eks-prod", strings.Repeat("a", 63)))

	assert.Error(t, validateClusterNamespace("eks-prod", ""))
	assert.Error(t, validateClusterNamespace("eks-prod", strings.Repeat("a", 64)))
	assert.Error(t, validateClusterNamespace("eks-prod", "payments,"))
	assert.Error(t, validateClusterNamespace("eks-prod", "pay ments"))
	assert.Error(t, validateClusterNamespace("eks-prod", "payments-"))
	assert.Error(t, validateClusterNamespace("eks-prod", "pay_ments"))
	assert.Error(t, validateClusterNamespace("eks-prod,", "payments"))
	assert.Error(t, validateClusterNamespace("", "payments"))
}

func TestRbacAddPathRejectsInvalidGrant(t *testing.T) {
	r := chi.NewRouter()
	r.Route("/rbac", Rbac)

	bodies := []string{
		`{"paths": ["*"]}`,
		`{"paths": ["/detector/eks-prod/payments,*"]}`,
		`{"paths": ["/clusters/eks-prod*", ""]}`,
		`{"paths": ["/detector/*/payments"]}`,
		`{"paths": ["/detector/eks-prod/pay ments*"]}`,
	}
	for _, b := range bodies {
		req := httptest.NewRequest(http.MethodPost, "/rbac/payments-team/addpath/", strings.NewReader(b))
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusBadRequest, rec.Code, b)
	}
}
