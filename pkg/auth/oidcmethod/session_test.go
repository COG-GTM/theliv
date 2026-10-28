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
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fidelity/theliv/internal/rbac"
	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	testHost     = "theliv.test"
	testIssuer   = "https://idp.test"
	testClientID = "theliv-client"
)

func useTestKey(t *testing.T) {
	t.Helper()
	old := jwtKey
	jwtKey = []byte("test-signing-key")
	t.Cleanup(func() { jwtKey = old })
}

func signSession(t *testing.T, method jwt.SigningMethod, claims jwt.Claims) string {
	t.Helper()
	s, err := jwt.NewWithClaims(method, claims).SignedString(jwtKey)
	require.NoError(t, err)
	return s
}

func requestWithSession(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/theliv-api/v1/clusters", nil)
	for _, c := range splitCookie(IDTokenKey, token) {
		r.AddCookie(c)
	}
	return r
}

func sessionUser(iat, exp int64) *rbac.UserInfo {
	u := &rbac.UserInfo{Upn: "mallory@acme.test", Roles: []string{"team-payments"}}
	u.Id = "mallory"
	u.IssuedAt = iat
	u.ExpiresAt = exp
	return u
}

// fakeIdP serves an OAuth2 token endpoint returning an RS256 id_token and
// installs a go-oidc verifier that trusts its key.
func fakeIdP(t *testing.T, idTokenExp time.Time) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	idToken, err := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":         testIssuer,
		"aud":         testClientID,
		"sub":         "mallory",
		"iat":         time.Now().Unix(),
		"exp":         idTokenExp.Unix(),
		"upn":         "Mallory@acme.test",
		"email":       "mallory@acme.test",
		"displayName": "Mallory",
		"groups":      []string{"team-payments"},
	}).SignedString(key)
	require.NoError(t, err)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "idp-access-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
			"id_token":     idToken,
		})
	}))
	t.Cleanup(srv.Close)

	oldVerifier, oldConfig := verifier, oauthConfigs[testHost]
	verifier = oidc.NewVerifier(testIssuer, &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{key.Public()}},
		&oidc.Config{ClientID: testClientID})
	oauthConfigs[testHost] = &oauth2.Config{
		ClientID:     testClientID,
		ClientSecret: "client-secret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   srv.URL + "/authorize",
			TokenURL:  srv.URL + "/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
	t.Cleanup(func() {
		verifier = oldVerifier
		if oldConfig == nil {
			delete(oauthConfigs, testHost)
		} else {
			oauthConfigs[testHost] = oldConfig
		}
	})
}

func exchange(t *testing.T) (*http.Request, *rbac.UserInfo) {
	t.Helper()
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/callback?code=abc&state=/", nil)
	require.NoError(t, ExchangeToken(rec, r))

	next := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/theliv-api/v1/clusters", nil)
	for _, c := range rec.Result().Cookies() {
		next.AddCookie(c)
	}
	raw, err := joinCookies(context.Background(), IDTokenKey, next.Cookies())
	require.NoError(t, err)
	claims := &rbac.UserInfo{}
	_, _, err = jwt.NewParser().ParseUnverified(raw, claims)
	require.NoError(t, err)
	return next, claims
}

func TestExchangeTokenIssuesSecondsExpiry(t *testing.T) {
	useTestKey(t)
	fakeIdP(t, time.Now().Add(24*time.Hour))

	before := time.Now().Unix()
	next, claims := exchange(t)
	after := time.Now().Unix()

	assert.Len(t, strconv.FormatInt(claims.ExpiresAt, 10), 10, "exp must be Unix seconds")
	assert.GreaterOrEqual(t, claims.IssuedAt, before)
	assert.LessOrEqual(t, claims.IssuedAt, after)
	assert.Equal(t, int64(sessionTTL/time.Second), claims.ExpiresAt-claims.IssuedAt)

	_, err := CheckAuthorization(next)
	assert.NoError(t, err)
	user, err := OIDC{}.GetUser(next, true)
	require.NoError(t, err)
	assert.Equal(t, "mallory", user.UID)
	assert.Equal(t, []string{"team-payments"}, user.AdGroups)
}

func TestExchangeTokenUsesShorterIdPExpiry(t *testing.T) {
	useTestKey(t)
	idpExp := time.Now().Add(10 * time.Minute)
	fakeIdP(t, idpExp)

	_, claims := exchange(t)
	assert.Equal(t, idpExp.Unix(), claims.ExpiresAt)
}

func TestSetSessionExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)

	u := &rbac.UserInfo{}
	setSessionExpiry(u, nil, now)
	assert.Equal(t, now.Unix(), u.IssuedAt)
	assert.Equal(t, now.Add(sessionTTL).Unix(), u.ExpiresAt)

	setSessionExpiry(u, jwt.NewNumericDate(now.Add(5*time.Hour)), now)
	assert.Equal(t, now.Add(sessionTTL).Unix(), u.ExpiresAt)

	setSessionExpiry(u, jwt.NewNumericDate(now.Add(5*time.Minute)), now)
	assert.Equal(t, now.Add(5*time.Minute).Unix(), u.ExpiresAt)
}

func TestSessionTokenValidation(t *testing.T) {
	useTestKey(t)
	now := time.Now()
	hour := int64(time.Hour / time.Second)

	fresh := signSession(t, jwt.SigningMethodHS256, sessionUser(now.Unix(), now.Unix()+hour))
	_, err := CheckAuthorization(requestWithSession(fresh))
	assert.NoError(t, err, "fresh session must be accepted")

	cases := map[string]string{
		"issued over an hour ago": signSession(t, jwt.SigningMethodHS256,
			sessionUser(now.Unix()-2*hour, now.Unix()-hour)),
		"legacy millisecond exp without iat": signSession(t, jwt.SigningMethodHS256,
			sessionUser(0, now.Add(time.Hour).UnixMilli())),
		"millisecond exp with iat": signSession(t, jwt.SigningMethodHS256,
			sessionUser(now.Unix(), now.Add(time.Hour).UnixMilli())),
		"no exp": signSession(t, jwt.SigningMethodHS256, sessionUser(now.Unix(), 0)),
		"no iat": signSession(t, jwt.SigningMethodHS256, sessionUser(0, now.Unix()+hour)),
		"lifetime longer than sessionTTL": signSession(t, jwt.SigningMethodHS256,
			sessionUser(now.Unix()-60, now.Unix()+hour)),
		"issued in the future": signSession(t, jwt.SigningMethodHS256,
			sessionUser(now.Unix()+600, now.Unix()+900)),
		"wrong HMAC algorithm": signSession(t, jwt.SigningMethodHS512,
			sessionUser(now.Unix(), now.Unix()+hour)),
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, sessionUser(now.Unix(), now.Unix()+hour)).
		SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	cases["alg none"] = none

	for name, token := range cases {
		t.Run(name, func(t *testing.T) {
			r := requestWithSession(token)
			_, err := CheckAuthorization(r)
			assert.True(t, errors.Is(err, ErrInvalidSession), "got %v", err)
			_, err = OIDC{}.GetUser(r, true)
			assert.Error(t, err)
		})
	}
}

func TestCheckAuthorizationWithoutCookie(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "http://"+testHost+"/theliv-api/v1/clusters", nil)
	_, err := CheckAuthorization(r)
	assert.Equal(t, ErrNoIDFound, err)
}

func TestExpiredSessionRestartsLogin(t *testing.T) {
	useTestKey(t)
	fakeIdP(t, time.Now().Add(time.Hour))
	now := time.Now()
	stale := signSession(t, jwt.SigningMethodHS256, sessionUser(now.Add(-2*time.Hour).Unix(), now.Add(-time.Hour).Unix()))

	r := requestWithSession(stale)
	_, err := CheckAuthorization(r)
	require.ErrorIs(t, err, ErrInvalidSession)

	rec := httptest.NewRecorder()
	HandleStartAuthFlow(rec, r)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("X-Location"), "/authorize")
}
