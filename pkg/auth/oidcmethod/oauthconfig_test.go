/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/fidelity/theliv/pkg/config"
	"golang.org/x/oauth2"
)

func testOauthConfig() *oauth2.Config {
	return newOauthConfig(&config.OidcConfig{
		ClientID:     "theliv-client",
		ClientSecret: "secret",
		CallBackHost: "https://theliv.example.com",
		CallBack:     "/theliv-api/v1/auth/callback",
	}, oauth2.Endpoint{
		AuthURL:  "https://idp.example.com/authorize",
		TokenURL: "https://idp.example.com/token",
	})
}

func withOauthConfig(t *testing.T, oc *oauth2.Config) {
	t.Helper()
	prev := oauthConfig
	oauthConfig = oc
	t.Cleanup(func() { oauthConfig = prev })
}

func TestNewOauthConfigUsesConfiguredRedirect(t *testing.T) {
	oc := testOauthConfig()
	if oc.RedirectURL != "https://theliv.example.com/theliv-api/v1/auth/callback" {
		t.Fatalf("unexpected redirect url %q", oc.RedirectURL)
	}
	if oc.ClientID != "theliv-client" || oc.Endpoint.AuthURL != "https://idp.example.com/authorize" {
		t.Fatalf("unexpected config %+v", oc)
	}
}

// Run with -race: concurrent unauthenticated requests with attacker-chosen
// Host headers must neither race nor depend on the Host header.
func TestHandleStartAuthFlowConcurrentDistinctHosts(t *testing.T) {
	oc := testOauthConfig()
	withOauthConfig(t, oc)

	const n = 200
	locations := make([]string, n)
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/clusters", nil)
			r.Host = fmt.Sprintf("attacker-%d.example.net", i)
			w := httptest.NewRecorder()
			HandleStartAuthFlow(w, r)
			codes[i] = w.Code
			locations[i] = w.Header().Get("X-Location")
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		if codes[i] != http.StatusUnauthorized {
			t.Fatalf("request %d: got status %d, want 401", i, codes[i])
		}
		if locations[i] != locations[0] {
			t.Fatalf("request %d: auth URL depends on Host header: %q vs %q", i, locations[i], locations[0])
		}
	}
	u, err := url.Parse(locations[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("redirect_uri"); got != oc.RedirectURL {
		t.Fatalf("redirect_uri = %q, want %q", got, oc.RedirectURL)
	}
	if getOauthConfig() != oc {
		t.Fatal("oauth config was replaced while serving requests")
	}
}

func TestHandleStartAuthFlowUninitialized(t *testing.T) {
	withOauthConfig(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/clusters", nil)
	w := httptest.NewRecorder()
	HandleStartAuthFlow(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("got status %d, want 503", w.Code)
	}
	if w.Header().Get("X-Location") != "" {
		t.Fatal("unexpected X-Location header")
	}
}

func TestExchangeTokenUninitialized(t *testing.T) {
	withOauthConfig(t, nil)
	r := httptest.NewRequest(http.MethodGet, "/theliv-api/v1/auth/callback?code=abc", nil)
	if err := ExchangeToken(httptest.NewRecorder(), r); err == nil {
		t.Fatal("expected error when OIDC is not initialized")
	}
}
