/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fidelity/theliv/pkg/config"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

const (
	testClientID    = "theliv-test"
	testAccessToken = "idp-access-token-value"
)

func newFakeIdP(t *testing.T) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                srv.URL,
			"authorization_endpoint":                srv.URL + "/authorize",
			"token_endpoint":                        srv.URL + "/token",
			"jwks_uri":                              srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"iss":   srv.URL,
			"aud":   testClientID,
			"sub":   "alice",
			"iat":   time.Now().Unix(),
			"exp":   time.Now().Add(time.Hour).Unix(),
			"upn":   "alice@acme.example",
			"email": "alice@acme.example",
		}).SignedString(key)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": testAccessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "k8s"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "oidc:\n" +
		"  oidcProvider: " + srv.URL + "\n" +
		"  callBack: /auth/callback\n" +
		"  callBackHost: https://theliv.acme.example\n" +
		"  clientID: " + testClientID + "\n" +
		"  clientSecret: test-secret\n"
	cfgFile := filepath.Join(dir, "theliv.yaml")
	if err := os.WriteFile(cfgFile, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	config.NewFileConfigLoader(cfgFile).LoadConfigs()

	p, err := oidc.NewProvider(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	prevProvider, prevVerifier, prevKey := provider, verifier, jwtKey
	provider = p
	verifier = oidc.NewVerifier(srv.URL, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}},
		&oidc.Config{ClientID: testClientID})
	jwtKey = []byte("test-secret")
	oauthConfigs = map[string]*oauth2.Config{}
	t.Cleanup(func() {
		provider, verifier, jwtKey = prevProvider, prevVerifier, prevKey
		oauthConfigs = map[string]*oauth2.Config{}
	})
	return srv
}

// TLS is terminated by nginx, so the Go server sees plain-HTTP requests.
func TestExchangeTokenDoesNotStoreAccessTokenBehindTLSTerminator(t *testing.T) {
	newFakeIdP(t)

	req := httptest.NewRequest(http.MethodGet, "http://localhost:8090/auth/callback?code=abc&state=/theliv/", nil)
	if req.TLS != nil {
		t.Fatal("expected a plain-HTTP request")
	}
	rec := httptest.NewRecorder()
	if err := ExchangeToken(rec, req); err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}

	setCookies := rec.Result().Header.Values("Set-Cookie")
	if len(setCookies) == 0 {
		t.Fatal("no cookies set")
	}
	for _, raw := range setCookies {
		if strings.Contains(raw, testAccessToken) {
			t.Errorf("access token leaked into Set-Cookie: %s", raw)
		}
	}

	var sawIDToken, sawAccessExpiry bool
	for _, c := range rec.Result().Cookies() {
		if !c.Secure || !c.HttpOnly {
			t.Errorf("cookie %q must be Secure and HttpOnly", c.Name)
		}
		switch {
		case c.Name == AccessTokenKey:
			sawAccessExpiry = true
			if c.Value != "" || c.MaxAge >= 0 {
				t.Errorf("access_token cookie must only be expired, got value=%q maxAge=%d", c.Value, c.MaxAge)
			}
		case strings.HasPrefix(c.Name, IDTokenKey):
			sawIDToken = true
		}
	}
	if !sawIDToken {
		t.Error("id_token session cookie was not set")
	}
	if !sawAccessExpiry {
		t.Error("legacy access_token cookie was not expired")
	}
}

func TestSessionCookiesAreSecure(t *testing.T) {
	for _, c := range append(splitCookie(IDTokenKey, strings.Repeat("x", 2*maxValueLength+1)), expiredCookie(AccessTokenKey)) {
		if !c.Secure || !c.HttpOnly {
			t.Errorf("cookie %q must be Secure and HttpOnly", c.Name)
		}
	}
}
