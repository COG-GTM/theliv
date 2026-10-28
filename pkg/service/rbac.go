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

var ErrInvalidGrant = errors.New("invalid grant path")

// ValidateGrant rejects grant paths that would not round-trip through the
// comma-separated role value or that would grant more than a path prefix.
// A grant must start with "/", must not contain the separator or whitespace,
// and may only use "*" as its final character.
func ValidateGrant(path string) error {
	if !strings.HasPrefix(path, "/") {
		return fmt.Errorf("%w %q: must start with /", ErrInvalidGrant, path)
	}
	if strings.ContainsFunc(path, func(r rune) bool { return r == ',' || unicode.IsSpace(r) || unicode.IsControl(r) }) {
		return fmt.Errorf("%w %q: must not contain commas or whitespace", ErrInvalidGrant, path)
	}
	if i := strings.Index(path, "*"); i != -1 && i != len(path)-1 {
		return fmt.Errorf("%w %q: * is only allowed at the end", ErrInvalidGrant, path)
	}
	return nil
}

// This function will insert new Role kv into database, if key not found.
// If KV exists in database, append newly added path.
// Value in database is string format, a collection seperated by ",".
// If database operation failed, return error, else return nil.
func AddPath(roleName string, newPaths []string) (err error) {
	for _, p := range newPaths {
		if err = ValidateGrant(p); err != nil {
			return
		}
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
