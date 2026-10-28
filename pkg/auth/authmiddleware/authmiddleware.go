/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package authmiddleware

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/fidelity/theliv/internal/rbac"
	"github.com/fidelity/theliv/pkg/auth/localmethod"
	"github.com/fidelity/theliv/pkg/auth/oidcmethod"
	"github.com/fidelity/theliv/pkg/config"
)

var ErrNotThisAuth = errors.New("not this Auth method")
var ErrNoAuthMethod = errors.New("no auth method bound to request")

type authMethodKey struct{}

func StartAuth(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//whitelist path
		oidc := config.GetThelivConfig().Oidc
		callBackPath := ""
		if oidc != nil {
			callBackPath = getUrlPath(oidc.CallBack)
		}
		if r.URL.Path == "/theliv-api/v1/health" || r.URL.Path == "/theliv-api/v1/metrics" || (callBackPath != "" && r.URL.Path == callBackPath) {
			handler.ServeHTTP(w, r)
			return
		}
		//local auth
		r, err := localmethod.CheckAuthorization(r)
		if err == nil {
			r = withAuthMethod(r, localmethod.Localinfo{})
			ok, err := checkRBAC(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if ok {
				handler.ServeHTTP(w, r)
			} else {
				http.Error(w, "", http.StatusForbidden)
			}
			return
		}
		if err.Error() == ErrNotThisAuth.Error() && oidc != nil {
			//oidc auth
			r, err = oidcmethod.CheckAuthorization(r)
			if err == nil {
				r = withAuthMethod(r, oidcmethod.OIDC{})
				ok, err := checkRBAC(r)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				if ok {
					handler.ServeHTTP(w, r)
				} else {
					http.Error(w, "", http.StatusForbidden)
				}
				return
			}
			if err == oidcmethod.ErrNoIDFound {
				oidcmethod.HandleStartAuthFlow(w, r)
				return
			}
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	})
}

func withAuthMethod(r *http.Request, method rbac.RBACInfo) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authMethodKey{}, method))
}

// GetUser resolves the user with the auth method StartAuth bound to this request.
func GetUser(r *http.Request, getAds bool) (*rbac.User, error) {
	method, ok := r.Context().Value(authMethodKey{}).(rbac.RBACInfo)
	if !ok || method == nil {
		return nil, ErrNoAuthMethod
	}
	return method.GetUser(r, getAds)
}

func getUrlPath(p string) string {
	if u, err := url.Parse(p); err == nil {
		return u.Path
	}
	return ""
}
