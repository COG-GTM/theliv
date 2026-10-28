/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

type fakeRoleStore struct {
	roles map[string][]string
}

func (f *fakeRoleStore) addPath(roleName string, paths []string) error {
	f.roles[roleName] = append(f.roles[roleName], paths...)
	return nil
}

func setupRbacTest(t *testing.T, grants []string, grantsErr error) (*fakeRoleStore, http.Handler) {
	store := &fakeRoleStore{roles: map[string][]string{"team-a-role": {"/clusters/a*"}}}
	origGrants, origAdd := callerGrants, addRolePaths
	callerGrants = func(*http.Request) ([]string, error) { return grants, grantsErr }
	addRolePaths = store.addPath
	t.Cleanup(func() { callerGrants, addRolePaths = origGrants, origAdd })
	r := chi.NewRouter()
	r.Route("/rbac", Rbac)
	return store, r
}

func postAddPath(h http.Handler, role, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/rbac/"+role+"/addpath", strings.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAddPathRejectsEscalationFromDelegatedManager(t *testing.T) {
	delegated := []string{"/rbac/team-a-role/addpath"}
	for _, body := range []string{
		`{"paths": ["*"]}`,
		`{"paths": ["/rbac*"]}`,
		`{"paths": ["/rbac/*"]}`,
		`{"paths": ["/register*"]}`,
		`{"paths": ["/clusters/a,*"]}`,
		`{"paths": ["/rbac/team-a-role/addpath", "/register*"]}`,
	} {
		store, h := setupRbacTest(t, delegated, nil)
		w := postAddPath(h, "team-a-role", body)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden}, w.Code, body)
		assert.Equal(t, []string{"/clusters/a*"}, store.roles["team-a-role"], body)
	}
}

func TestAddPathStatusCodes(t *testing.T) {
	tests := []struct {
		name   string
		grants []string
		role   string
		body   string
		want   int
	}{
		{"global wildcard is invalid", []string{"*"}, "team-a-role", `{"paths": ["*"]}`, http.StatusBadRequest},
		{"comma list is invalid", []string{"*"}, "team-a-role", `{"paths": ["/a,/b"]}`, http.StatusBadRequest},
		{"whitespace is invalid", []string{"*"}, "team-a-role", `{"paths": ["/a b"]}`, http.StatusBadRequest},
		{"invalid role name", []string{"*"}, "a,admin", `{"paths": ["/clusters/a*"]}`, http.StatusBadRequest},
		{"missing paths", []string{"*"}, "team-a-role", `{"paths": []}`, http.StatusBadRequest},
		{"not covered", []string{"/clusters/a*"}, "team-a-role", `{"paths": ["/clusters*"]}`, http.StatusForbidden},
		{"admin may grant rbac subtree", []string{"*"}, "team-a-role", `{"paths": ["/rbac/*"]}`, http.StatusOK},
		{"delegate may pass on what it holds", []string{"/clusters/a*"}, "team-a-role", `{"paths": ["/clusters/a/ns*"]}`, http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, h := setupRbacTest(t, tt.grants, nil)
			assert.Equal(t, tt.want, postAddPath(h, tt.role, tt.body).Code)
		})
	}
}

func TestAddPathGrantLookupFailure(t *testing.T) {
	store, h := setupRbacTest(t, nil, errors.New("etcd down"))
	w := postAddPath(h, "team-a-role", `{"paths": ["/clusters/a/ns*"]}`)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, []string{"/clusters/a*"}, store.roles["team-a-role"])
}

func TestAddPathStoresCoveredPaths(t *testing.T) {
	store, h := setupRbacTest(t, []string{"*"}, nil)
	w := postAddPath(h, "team-a-role", `{"paths": ["/detector/a/ns*"]}`)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []string{"/clusters/a*", "/detector/a/ns*"}, store.roles["team-a-role"])
}
