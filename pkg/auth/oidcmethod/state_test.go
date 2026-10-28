/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testHost = "https://theliv.acme.example"

func stubExchange(t *testing.T) *int {
	t.Helper()
	calls := 0
	orig := exchangeToken
	exchangeToken = func(w http.ResponseWriter, r *http.Request) error {
		calls++
		return nil
	}
	t.Cleanup(func() { exchangeToken = orig })
	return &calls
}

// startLogin runs newLoginState and returns the state plus the cookies the browser would store.
func startLogin(t *testing.T, returnPath string) (string, []*http.Cookie) {
	t.Helper()
	rec := httptest.NewRecorder()
	state, err := newLoginState(rec, returnPath, true)
	if err != nil {
		t.Fatalf("newLoginState: %v", err)
	}
	return state, rec.Result().Cookies()
}

func callbackRequest(state string, cookies []*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+url.QueryEscape(state), nil)
	for _, c := range cookies {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	return r
}

func TestNewLoginStateCookie(t *testing.T) {
	state, cookies := startLogin(t, "/theliv/clusters/a")
	if !isValidStateNonce(state) {
		t.Fatalf("state %q is not a random nonce", state)
	}
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	c := cookies[0]
	if c.Name != StateCookiePrefix+state || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.MaxAge <= 0 {
		t.Fatalf("unexpected state cookie: %+v", c)
	}
	other, _ := startLogin(t, "/")
	if other == state {
		t.Fatal("state must be unique per login")
	}
}

func TestCallbackRedirectsToStoredPath(t *testing.T) {
	calls := stubExchange(t)
	state, cookies := startLogin(t, "/theliv/clusters/a?ns=b")
	rec := httptest.NewRecorder()
	handleCallback(rec, callbackRequest(state, cookies), testHost)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != testHost+"/theliv/clusters/a?ns=b" {
		t.Fatalf("Location = %q", got)
	}
	if *calls != 1 {
		t.Fatalf("exchange called %d times", *calls)
	}
	cleared := false
	for _, c := range rec.Result().Cookies() {
		if c.Name == StateCookiePrefix+state && c.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("state cookie was not cleared")
	}
}

func TestCallbackRejectsAttackerState(t *testing.T) {
	for _, state := range []string{".evil.example", "@evil.example", ":443@evil.example", "//evil.example", "/theliv/", ""} {
		t.Run(state, func(t *testing.T) {
			calls := stubExchange(t)
			// victim has a pending login of their own, which must not help the attacker
			_, cookies := startLogin(t, "/theliv/")
			rec := httptest.NewRecorder()
			handleCallback(rec, callbackRequest(state, cookies), testHost)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != "" {
				t.Fatalf("unexpected redirect to %q", loc)
			}
			if *calls != 0 {
				t.Fatal("code must not be exchanged when state is invalid")
			}
		})
	}
}

func TestCallbackRejectsMismatchedState(t *testing.T) {
	calls := stubExchange(t)
	// Mallory's state from her own browser, replayed against Alice who has no / a different cookie.
	malloryState, _ := startLogin(t, "/")
	_, aliceCookies := startLogin(t, "/")
	for _, cookies := range [][]*http.Cookie{nil, aliceCookies} {
		rec := httptest.NewRecorder()
		handleCallback(rec, callbackRequest(malloryState, cookies), testHost)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	}
	if *calls != 0 {
		t.Fatal("code must not be exchanged when state is mismatched")
	}
}

func TestCallbackStateIsSingleUse(t *testing.T) {
	stubExchange(t)
	state, cookies := startLogin(t, "/")
	rec := httptest.NewRecorder()
	handleCallback(rec, callbackRequest(state, cookies), testHost)
	if rec.Code != http.StatusFound {
		t.Fatalf("first callback status = %d", rec.Code)
	}
	var remaining []*http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge >= 0 {
			remaining = append(remaining, c)
		}
	}
	rec = httptest.NewRecorder()
	handleCallback(rec, callbackRequest(state, remaining), testHost)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("replayed callback status = %d, want 400", rec.Code)
	}
}

func TestCallbackConcurrentLoginsDoNotClobber(t *testing.T) {
	stubExchange(t)
	first, c1 := startLogin(t, "/theliv/one")
	_, c2 := startLogin(t, "/theliv/two")
	rec := httptest.NewRecorder()
	handleCallback(rec, callbackRequest(first, append(c1, c2...)), testHost)
	if got := rec.Header().Get("Location"); got != testHost+"/theliv/one" {
		t.Fatalf("Location = %q", got)
	}
}

func TestStoredReturnPathCannotLeaveHost(t *testing.T) {
	stubExchange(t)
	for _, p := range []string{".evil.example", "@evil.example", ":443@evil.example", "//evil.example", "/\\evil.example", "https://evil.example", "/theliv/\r\nSet-Cookie:x=y"} {
		t.Run(p, func(t *testing.T) {
			state, cookies := startLogin(t, p)
			rec := httptest.NewRecorder()
			handleCallback(rec, callbackRequest(state, cookies), testHost)
			loc := rec.Header().Get("Location")
			if loc != testHost+"/" {
				t.Fatalf("Location = %q, want %q", loc, testHost+"/")
			}
		})
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]string{
		"/":                          "/",
		"/theliv/":                   "/theliv/",
		"/theliv/a?b=c#d":            "/theliv/a?b=c#d",
		"":                           "/",
		".evil.example":              "/",
		"@evil.example":              "/",
		":443@evil.example":          "/",
		"//evil.example":             "/",
		"/\\evil.example":            "/",
		"/theliv\\..\\evil":          "/",
		"https://evil.example/":      "/",
		"javascript:alert(1)":        "/",
		"/theliv/\tx":                "/",
		"/theliv/%2F%2Fevil.example": "/theliv/%2F%2Fevil.example",
	}
	for in, want := range cases {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestRedirectTarget(t *testing.T) {
	cases := []struct{ host, path, want string }{
		{testHost, "/theliv/a", testHost + "/theliv/a"},
		{testHost + "/", "/theliv/a", testHost + "/theliv/a"},
		{testHost, ".evil.example", testHost + "/"},
		{testHost, "@evil.example", testHost + "/"},
		{testHost, "/theliv/%2F%2Fevil.example", testHost + "/theliv/%2F%2Fevil.example"},
		{"", "/theliv/a", "/theliv/a"},
	}
	for _, c := range cases {
		got := redirectTarget(c.host, c.path)
		if got != c.want {
			t.Errorf("redirectTarget(%q, %q) = %q, want %q", c.host, c.path, got, c.want)
		}
		if u, _ := url.Parse(got); u.Host != "" && !strings.HasSuffix(testHost, u.Host) {
			t.Errorf("redirectTarget(%q, %q) left host: %q", c.host, c.path, got)
		}
	}
}
