/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/fidelity/theliv/internal/rbac"
	"github.com/fidelity/theliv/pkg/config"
	log "github.com/fidelity/theliv/pkg/log"
	"github.com/go-chi/render"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

const (
	AccessTokenKey string = "access_token"
	IDTokenKey     string = "id_token"

	// sessionTTL bounds the lifetime of the Theliv session token and cookie.
	sessionTTL = time.Hour
	// sessionClockSkew tolerates small clock differences between replicas.
	sessionClockSkew = time.Minute
)

var provider *oidc.Provider

var oauthConfigs = make(map[string]*oauth2.Config)
var jwtKey []byte
var ErrNoIDFound = errors.New("no id token found")
var ErrInvalidSession = errors.New("session token invalid or expired")

type OIDC struct {
}

// Initialize oidc config
func InitAuth() error {
	if provider != nil {
		return nil
	}
	oicdConfig := config.GetThelivConfig().Oidc
	if oicdConfig == nil {
		log.S().Info("OIDC config not provided, skipping OIDC initialization")
		return nil
	}
	p, err := oidc.NewProvider(context.Background(), oicdConfig.OidcProvider)
	if err != nil {
		log.S().Errorf("Unable to initialize oidc config: %v", err)
		return err
	}
	provider = p

	oidcConfig := &oidc.Config{
		ClientID: oicdConfig.ClientID,
	}
	verifier = provider.Verifier(oidcConfig)
	jwtKey = []byte(oicdConfig.ClientSecret)
	return nil
}

func (OIDC) GetUser(r *http.Request, getAd bool) (*rbac.User, error) {
	c, err := joinCookies(r.Context(), IDTokenKey, r.Cookies())
	if err != nil {
		log.SWithContext(r.Context()).Warnf("Cookie %v does not exist: %v", IDTokenKey, err)
		return nil, err
	}
	extract, err := userFromToken(r.Context(), c)
	if err != nil {
		return nil, err
	}
	user := rbac.User{}
	user.UID = extract.Id
	user.Surname = extract.FamilyName
	user.Givenname = extract.GivenName
	user.Displayname = extract.Name
	user.Emailaddress = extract.Email
	if getAd {
		user.AdGroups = extract.Roles
	}
	return &user, nil
}

func userFromToken(ctx context.Context, auth string) (*rbac.UserInfo, error) {
	user := &rbac.UserInfo{}
	parser := jwt.NewParser(jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	token, err := parser.ParseWithClaims(auth, user, func(t *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil {
		log.SWithContext(ctx).Errorf("authorization code/cookie invalid")
		return nil, err
	}
	c, ok := token.Claims.(*rbac.UserInfo)
	if !ok {
		msg := "cannot unmarshal ID token claim"
		err := fmt.Errorf("%s", msg)
		log.SWithContext(ctx).Error(msg)
		return nil, err
	}
	if e := c.Valid(); e != nil {
		log.SWithContext(ctx).Errorf("failed to validate token")
		return nil, e
	}
	if e := validateSessionLifetime(c, time.Now()); e != nil {
		log.SWithContext(ctx).Errorf("failed to validate token: %v", e)
		return nil, e
	}
	return user, nil
}

// validateSessionLifetime requires iat/exp in Unix seconds describing a
// session no longer than sessionTTL. Tokens without an expiry, or with an
// expiry far in the future (e.g. legacy tokens whose exp was written in
// milliseconds), are rejected.
func validateSessionLifetime(c *rbac.UserInfo, now time.Time) error {
	if c.ExpiresAt == 0 || c.IssuedAt == 0 {
		return fmt.Errorf("%w: missing exp or iat", ErrInvalidSession)
	}
	ttl := int64(sessionTTL / time.Second)
	skew := int64(sessionClockSkew / time.Second)
	t := now.Unix()
	if c.ExpiresAt <= t {
		return fmt.Errorf("%w: token expired", ErrInvalidSession)
	}
	if c.IssuedAt > t+skew {
		return fmt.Errorf("%w: token issued in the future", ErrInvalidSession)
	}
	if c.ExpiresAt-c.IssuedAt > ttl || c.ExpiresAt > t+ttl+skew {
		return fmt.Errorf("%w: token lifetime exceeds %v", ErrInvalidSession, sessionTTL)
	}
	return nil
}

func CheckAuthorization(r *http.Request) (*http.Request, error) {
	found := false
	for _, cookie := range r.Cookies() {
		if strings.HasPrefix(cookie.Name, IDTokenKey) {
			found = true
			break
		}
	}
	if !found {
		return r, ErrNoIDFound
	}
	c, err := joinCookies(r.Context(), IDTokenKey, r.Cookies())
	if err != nil {
		return r, ErrInvalidSession
	}
	if _, err := userFromToken(r.Context(), c); err != nil {
		return r, ErrInvalidSession
	}
	return r, nil
}

func HandleStartAuthFlow(w http.ResponseWriter, r *http.Request) {
	state := getRedirectUrl(r.Header.Get("redirect"))
	if state == "" {
		state = "/"
	}
	// redirect to authorization url
	url := getOauthConfig(r).AuthCodeURL(state)
	w.Header().Add("X-Location", url)
	w.WriteHeader(http.StatusUnauthorized)
	render.JSON(w, r, struct {
		Error string `json:"error"`
		Code  int    `json:"code"`
		Login bool   `json:"login"`
	}{url, http.StatusUnauthorized, true})
}

func getRedirectUrl(url string) (redirect string) {
	redirect = "/theliv/"
	path := strings.Split(url, redirect)
	if len(path) == 2 {
		redirect = redirect + path[1]
	}
	return
}
