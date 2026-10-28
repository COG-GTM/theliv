/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	auth "github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/fidelity/theliv/pkg/database/etcd"
)

const (
	SEPARATOR       = ","
	maxRoleNameLen  = 256
	maxGrantPathLen = 512
)

var (
	ErrInvalidRoleName  = errors.New("invalid role name")
	ErrInvalidGrantPath = errors.New("invalid path")

	// One or more "/segment" parts, optionally ending in a single "*" or "/*".
	grantPathPattern = regexp.MustCompile(`^(/[A-Za-z0-9._~:@-]+)+/?\*?$`)
)

// ValidateRoleName rejects role names that are empty, too long, or contain
// characters that are separators in the role store or the request path.
func ValidateRoleName(roleName string) error {
	if roleName == "" || len(roleName) > maxRoleNameLen || roleName != strings.TrimSpace(roleName) ||
		roleName == "." || roleName == ".." {
		return fmt.Errorf("%w: %q", ErrInvalidRoleName, roleName)
	}
	for _, c := range roleName {
		if c < 0x20 || c == 0x7f || strings.ContainsRune(`,/\*%`, c) {
			return fmt.Errorf("%w: %q", ErrInvalidRoleName, roleName)
		}
	}
	return nil
}

// ValidateGrantPath accepts only absolute paths built from plain segments,
// with "*" allowed solely as the final character. Global wildcards ("*",
// "/*"), separators (","), whitespace and "."/".." segments are rejected.
func ValidateGrantPath(p string) error {
	if len(p) > maxGrantPathLen || !grantPathPattern.MatchString(p) {
		return fmt.Errorf("%w: %q", ErrInvalidGrantPath, p)
	}
	for _, segment := range strings.Split(strings.TrimSuffix(p, "*"), "/") {
		if segment == "." || segment == ".." {
			return fmt.Errorf("%w: %q", ErrInvalidGrantPath, p)
		}
	}
	return nil
}

// IsInvalidInput reports whether err was caused by an invalid role name or path.
func IsInvalidInput(err error) bool {
	return errors.Is(err, ErrInvalidRoleName) || errors.Is(err, ErrInvalidGrantPath)
}

// This function will insert new Role kv into database, if key not found.
// If KV exists in database, append newly added path.
// Value in database is string format, a collection seperated by ",".
// If database operation failed, return error, else return nil.
func AddPath(roleName string, newPaths []string) (err error) {
	if err = validateGrant(roleName, newPaths); err != nil {
		return
	}
	var updatedValue []string
	var value []byte
	rolePath := auth.RolePrefix + roleName
	value, err = etcd.Get(context.Background(), rolePath)
	if err != nil {
		return
	}
	existingValue := string(value)
	if len(existingValue) == 0 {
		updatedValue = newPaths
	} else {
		updatedValue = getUpdatedElement(strings.Split(existingValue, SEPARATOR), newPaths)
	}
	newValue := strings.Join(updatedValue, SEPARATOR)
	if existingValue == newValue {
		return
	}
	err = etcd.PutStr(rolePath, newValue)
	return
}

// This function will append element to the first array,
// which exists in the second array but non-existing in the first array.
func getUpdatedElement(existingElements []string, newElements []string) []string {
	for _, newVal := range newElements {
		matched := false
		for _, oldVal := range existingElements {
			if oldVal == newVal {
				matched = true
			}
		}
		if !matched {
			existingElements = append(existingElements, newVal)
		}
	}
	return existingElements
}

func validateGrant(roleName string, paths []string) error {
	if err := ValidateRoleName(roleName); err != nil {
		return err
	}
	for _, p := range paths {
		if err := ValidateGrantPath(p); err != nil {
			return err
		}
	}
	return nil
}
