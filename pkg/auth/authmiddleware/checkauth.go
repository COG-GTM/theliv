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
	"path"
	"strings"

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
	path, ok := requestPath(r)
	if !ok {
		return false, nil
	}
	if whitelist := config.GetThelivConfig().Auth.WhitelistPath; len(whitelist) > 0 {
		skip, err := checkPattern(whitelist[:], []string{path})
		if err != nil {
			return false, err
		}
		if skip {
			return true, err
		}
	}
	if path == URLPrefix || strings.HasPrefix(path, URLPrefix+"/") {
		path = path[len(URLPrefix):]
	} else {
		return false, err
	}
	roles, err := getRole(r.Context(), user.UID)
	if err != nil {
		return false, err
	}
	adgroups := user.AdGroups

	roles = append(roles, adgroups...)
	var grantPath []string
	for _, role := range roles {
		path, err := getPath(r.Context(), role)
		if err != nil {
			return false, err
		}
		if path != nil {
			grantPath = append(grantPath, path...)
		}
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

// requestPath returns the path the router dispatches on (the escaped form when the
// request carries percent-encoded characters), without a trailing slash.
// Paths with dot segments or empty segments are rejected, so a grant on "/a/b/*"
// can never be satisfied by a path that resolves outside "/a/b/".
func requestPath(r *http.Request) (string, bool) {
	p := r.URL.Path
	if r.URL.RawPath != "" {
		p = r.URL.RawPath
	}
	p = strings.TrimSuffix(p, "/")
	if p == "" || path.Clean(p) != p {
		return "", false
	}
	return p, true
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
// The * only matches whole path segments, everything after it is ignored:
//   - "/foo/*" matches "/foo" and everything under "/foo/".
//   - "/foo*" matches "/foo" and everything under "/foo/", but not "/foobar".
//   - "*" matches everything.
func KeyMatch(key1 string, key2 string) bool {

	key1 = CleanString(key1)
	key2 = CleanString(key2)

	i := strings.Index(key2, "*")
	if i == -1 {
		return key1 == key2
	}

	prefix := key2[:i]
	if prefix == "" {
		return true
	}
	prefix = strings.TrimSuffix(prefix, "/")
	return key1 == prefix || strings.HasPrefix(key1, prefix+"/")
}

// remove blank and line-breaks from string
func CleanString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", ""), " ", "")
}
