/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/fidelity/theliv/internal/rbac"
	"github.com/fidelity/theliv/pkg/config"
	"github.com/fidelity/theliv/pkg/database/etcd"
)

const UIDPrefix string = "/theliv/uids/"
const RolePrefix string = "/theliv/roles/"
const URLPrefix string = "/theliv-api/v1"

func getRole(ctx context.Context, UID string) ([]string, error) {
	UID = UIDPrefix + UID
	value, err := etcd.Get(ctx, UID)
	if err != nil {
		return nil, err
	}
	roles := strings.Split(string(value), ",")
	return roles[:], nil
}
func getPath(ctx context.Context, role string) ([]string, error) {
	role = RolePrefix + role
	value, err := etcd.Get(ctx, role)
	if err != nil {
		return nil, err
	}
	if len(value) < 1 {
		return nil, nil
	}
	paths := strings.Split(string(value), ",")
	return paths[:], nil
}

func checkRBAC(r *http.Request) (bool, error) {
	user, err := GetUser(r, true)
	if err != nil {
		return false, err
	}
	path := r.URL.Path
	path = strings.TrimSuffix(path, "/")
	skip, err := checkPattern([]string{path}, config.GetThelivConfig().Auth.WhitelistPath[:])
	if err != nil {
		return false, err
	}
	if skip {
		return true, err
	}
	if strings.HasPrefix(path, URLPrefix) {
		path = path[14:]
	} else {
		return false, err
	}
	grantPath, err := grantedPathsForUser(r.Context(), user)
	if err != nil {
		return false, err
	}
	if len(grantPath) < 1 {
		return false, nil
	}
	matched, err := checkPattern(grantPath[:], []string{path})
	if err != nil {
		return false, err
	}
	return matched, err
}

// GrantedPaths returns every path pattern granted to the user of the request,
// through the user's own roles and AD groups.
func GrantedPaths(r *http.Request) ([]string, error) {
	user, err := GetUser(r, true)
	if err != nil {
		return nil, err
	}
	return grantedPathsForUser(r.Context(), user)
}

func grantedPathsForUser(ctx context.Context, user *rbac.User) ([]string, error) {
	roles, err := getRole(ctx, user.UID)
	if err != nil {
		return nil, err
	}
	roles = append(roles, user.AdGroups...)
	var grantPath []string
	for _, role := range roles {
		path, err := getPath(ctx, role)
		if err != nil {
			return nil, err
		}
		if path != nil {
			grantPath = append(grantPath, path...)
		}
	}
	return grantPath, nil
}

// GrantCovers reports whether every request path matched by the pattern
// requested is also matched (see KeyMatch) by at least one of grants,
// i.e. whether a holder of grants may delegate requested.
func GrantCovers(grants []string, requested string) bool {
	reqPrefix, reqWildcard := wildcardPrefix(CleanString(requested))
	for _, grant := range grants {
		grant = CleanString(grant)
		if grant == "" {
			continue
		}
		grantPrefix, grantWildcard := wildcardPrefix(grant)
		if !grantWildcard {
			if !reqWildcard && reqPrefix == grant {
				return true
			}
			continue
		}
		if strings.HasPrefix(reqPrefix, grantPrefix) {
			return true
		}
	}
	return false
}

func wildcardPrefix(p string) (string, bool) {
	i := strings.Index(p, "*")
	if i == -1 {
		return p, false
	}
	return p[:i], true
}

// check any of string match any of the pattern
func checkPattern(patterns []string, strings []string) (bool, error) {
	matched := false
	if len(patterns) < 1 || len(strings) < 1 {
		return false, errors.New("pattern or string array is empty")
	}
	for _, s := range strings {
		for _, p := range patterns {
			matched = KeyMatch(s, p)
			if matched {
				return matched, nil
			}
		}
	}
	return matched, nil
}

// KeyMatch determines whether key1 matches the pattern of key2 (similar to RESTful path), key2 can contain a *.
// For example, "/foo/bar" matches "/foo/*"
// Ref: https://github.com/casbin/casbin/blob/master/util/builtin_operators.go
func KeyMatch(key1 string, key2 string) bool {

	key1 = CleanString(key1)
	key2 = CleanString(key2)

	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}

	if len(key1) > i {
		return key1[:i] == key2[:i]
	}
	return key1 == key2[:i]
}

// remove blank and line-breaks from string
func CleanString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), " ", "")
}
