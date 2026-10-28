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
	"strings"
	"unicode"

	auth "github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/fidelity/theliv/pkg/database/etcd"
)

const SEPARATOR = ","

var ErrInvalidPath = errors.New("invalid path")

// ValidatePaths rejects grants that would corrupt the comma-separated role value
// or grant access to every path.
func ValidatePaths(paths []string) error {
	for _, p := range paths {
		if p == "" {
			return fmt.Errorf("%w: empty path", ErrInvalidPath)
		}
		if strings.Contains(p, SEPARATOR) || strings.IndexFunc(p, unicode.IsSpace) != -1 {
			return fmt.Errorf("%w: %q contains a separator or whitespace", ErrInvalidPath, p)
		}
		if i := strings.Index(p, "*"); i != -1 && (i == 0 || i != len(p)-1) {
			return fmt.Errorf("%w: %q wildcard must be a trailing suffix of a non-empty prefix", ErrInvalidPath, p)
		}
	}
	return nil
}

// This function will insert new Role kv into database, if key not found.
// If KV exists in database, append newly added path.
// Value in database is string format, a collection seperated by ",".
// If database operation failed, return error, else return nil.
func AddPath(roleName string, newPaths []string) (err error) {
	if err = ValidatePaths(newPaths); err != nil {
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
