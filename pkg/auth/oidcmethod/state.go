/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// StateCookiePrefix names the per-login cookie that binds the OIDC state
	// to the browser that started the flow. The cookie value is the return path.
	StateCookiePrefix = "theliv_oidc_state_"
	stateMaxAge       = 10 * time.Minute
	stateNonceBytes   = 32
	defaultReturnPath = "/"
)

var ErrInvalidState = errors.New("invalid or expired login state")

var stateNonceLen = base64.RawURLEncoding.EncodedLen(stateNonceBytes)

// newLoginState generates a random state, stores the return path in a
// short-lived HttpOnly cookie keyed by that state and returns the state.
// One cookie per login attempt keeps concurrent 401s from overwriting each other.
func newLoginState(w http.ResponseWriter, returnPath string, secure bool) (string, error) {
	b := make([]byte, stateNonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	state := base64.RawURLEncoding.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{
		Name:     StateCookiePrefix + state,
		Value:    base64.RawURLEncoding.EncodeToString([]byte(safeReturnPath(returnPath))),
		Path:     "/",
		MaxAge:   int(stateMaxAge.Seconds()),
		Expires:  time.Now().Add(stateMaxAge),
		Secure:   secure,
		HttpOnly: true,
		// Lax so the cookie is sent on the IdP's top-level redirect back to the callback.
		SameSite: http.SameSiteLaxMode,
	})
	return state, nil
}

// consumeLoginState checks the state query parameter against the cookie set
// by newLoginState, clears all pending state cookies and returns the stored
// return path.
func consumeLoginState(w http.ResponseWriter, r *http.Request, secure bool) (string, error) {
	state := r.URL.Query().Get("state")
	var stored *http.Cookie
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, StateCookiePrefix) {
			continue
		}
		if isValidStateNonce(state) && c.Name == StateCookiePrefix+state {
			stored = c
		}
		http.SetCookie(w, &http.Cookie{
			Name:     c.Name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Expires:  time.Unix(0, 0),
			Secure:   secure,
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
		})
	}
	if stored == nil {
		return "", ErrInvalidState
	}
	p, err := base64.RawURLEncoding.DecodeString(stored.Value)
	if err != nil {
		return "", ErrInvalidState
	}
	return safeReturnPath(string(p)), nil
}

func isValidStateNonce(s string) bool {
	if len(s) != stateNonceLen {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(s)
	return err == nil
}

// safeReturnPath returns p if it is a local absolute path, otherwise "/".
func safeReturnPath(p string) string {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") || strings.ContainsRune(p, '\\') {
		return defaultReturnPath
	}
	for _, c := range p {
		if c < 0x20 || c == 0x7f {
			return defaultReturnPath
		}
	}
	u, err := url.Parse(p)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || !strings.HasPrefix(u.Path, "/") {
		return defaultReturnPath
	}
	return p
}

// redirectTarget resolves a validated return path against the configured
// callback host so the redirect can never leave that host.
func redirectTarget(host, returnPath string) string {
	ref, _ := url.Parse(safeReturnPath(returnPath))
	base, err := url.Parse(host)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return ref.String()
	}
	target := &url.URL{
		Scheme:   base.Scheme,
		Host:     base.Host,
		Path:     strings.TrimSuffix(base.Path, "/") + ref.Path,
		RawPath:  strings.TrimSuffix(base.EscapedPath(), "/") + ref.EscapedPath(),
		RawQuery: ref.RawQuery,
		Fragment: ref.Fragment,
	}
	return target.String()
}

func isSecureRequest(r *http.Request, host string) bool {
	return r.TLS != nil || strings.HasPrefix(strings.ToLower(host), "https://")
}
