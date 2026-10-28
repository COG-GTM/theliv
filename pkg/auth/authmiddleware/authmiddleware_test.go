/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/fidelity/theliv/internal/rbac"
)

type accessKeyMethod struct{}

func (accessKeyMethod) GetUser(r *http.Request, _ bool) (*rbac.User, error) {
	key := r.Header.Get("ACCESSKEY")
	if key == "" {
		return nil, errors.New("no ACCESSKEY header")
	}
	return &rbac.User{UID: "key:" + key}, nil
}

type cookieMethod struct{}

func (cookieMethod) GetUser(r *http.Request, _ bool) (*rbac.User, error) {
	c, err := r.Cookie("id_token")
	if err != nil {
		return nil, err
	}
	return &rbac.User{UID: "cookie:" + c.Value}, nil
}

func TestGetUserWithoutAuthMethod(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/userinfo", nil)
	r.Header.Set("ACCESSKEY", "k")
	if _, err := GetUser(r, false); !errors.Is(err, ErrNoAuthMethod) {
		t.Fatalf("expected ErrNoAuthMethod, got %v", err)
	}
}

func TestGetUserUsesMethodBoundToRequest(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/userinfo", nil)
	r.Header.Set("ACCESSKEY", "alice")
	r = withAuthMethod(r, accessKeyMethod{})

	// Binding a different method on another request must not affect r.
	other := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/userinfo", nil)
	other.AddCookie(&http.Cookie{Name: "id_token", Value: "x"})
	_ = withAuthMethod(other, cookieMethod{})

	user, err := GetUser(r, false)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if user.UID != "key:alice" {
		t.Fatalf("expected key:alice, got %s", user.UID)
	}
}

func TestGetUserConcurrentAccessKeyAndCookieRequests(t *testing.T) {
	const n = 500
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/userinfo", nil)
			r.Header.Set("ACCESSKEY", fmt.Sprintf("k%d", i))
			r = withAuthMethod(r, accessKeyMethod{})
			user, err := GetUser(r, false)
			if err != nil {
				errs <- fmt.Errorf("access key request %d: %w", i, err)
				return
			}
			if want := fmt.Sprintf("key:k%d", i); user.UID != want {
				errs <- fmt.Errorf("access key request %d: got %s want %s", i, user.UID, want)
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/userinfo", nil)
			r.AddCookie(&http.Cookie{Name: "id_token", Value: fmt.Sprintf("c%d", i)})
			r = withAuthMethod(r, cookieMethod{})
			user, err := GetUser(r, false)
			if err != nil {
				errs <- fmt.Errorf("cookie request %d: %w", i, err)
				return
			}
			if want := fmt.Sprintf("cookie:c%d", i); user.UID != want {
				errs <- fmt.Errorf("cookie request %d: got %s want %s", i, user.UID, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
