/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/fidelity/theliv/pkg/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const (
	MISS_PATHS_IN_BODY  = "paths field missing or empty in request body"
	SERVICE_UNAVAILABLE = "DB service Unavailable"
	ROLE_UPDATED        = "Role update success"
	GRANTS_UNAVAILABLE  = "Unable to resolve caller permissions"
	PATH_NOT_DELEGABLE  = "path %q is not covered by your own permissions"
)

var (
	callerGrants = authmiddleware.GrantedPaths
	addRolePaths = service.AddPath
)

type Paths struct {
	Paths []string `json:"paths"`
}

// Add POST /{roleName}/addpath operation
// PathParameter {roleName} should be a valid role name.
func Rbac(r chi.Router) {
	r.Route("/{roleName}/addpath", func(r chi.Router) {
		r.Post("/", addPath)
	})
}

// Request body should be in valid Json format, or 400 will be returned.
// Request body should include {"paths": [""]}, paths should be an unempty collection,
// or 400 will be returned.
// roleName and every path must pass service.ValidateRoleName/ValidateGrantPath,
// or 400 will be returned.
// Every path must be covered by the caller's own grants, or 403 will be returned.
// If backend DB operation failed, return 503.
// if backend DB operation success, return normal response.
func addPath(w http.ResponseWriter, r *http.Request) {
	roleName := chi.URLParam(r, "roleName")
	var paths Paths

	if err := service.ValidateRoleName(roleName); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := decodeBody(r.Body, &paths); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(paths.Paths) == 0 {
		http.Error(w, MISS_PATHS_IN_BODY, http.StatusBadRequest)
		return
	}
	for _, p := range paths.Paths {
		if err := service.ValidateGrantPath(p); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	grants, err := callerGrants(r)
	if err != nil {
		http.Error(w, GRANTS_UNAVAILABLE, http.StatusInternalServerError)
		return
	}
	for _, p := range paths.Paths {
		if !authmiddleware.GrantCovers(grants, p) {
			http.Error(w, fmt.Sprintf(PATH_NOT_DELEGABLE, p), http.StatusForbidden)
			return
		}
	}
	if err := addRolePaths(roleName, paths.Paths); err != nil {
		if service.IsInvalidInput(err) {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.Error(w, SERVICE_UNAVAILABLE, http.StatusServiceUnavailable)
		return
	}
	render.Respond(w, r, ROLE_UPDATED)
}

// This function will decode the http.Request.Body
// Decoded body will be unmarshaled to the object specified by the second parameter.
// If error occurred, return error.
func decodeBody(body io.ReadCloser, result interface{}) error {
	return json.NewDecoder(body).Decode(&result)
}
