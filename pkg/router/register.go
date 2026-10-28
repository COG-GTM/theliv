/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/fidelity/theliv/pkg/config"
	"github.com/fidelity/theliv/pkg/err"
	log "github.com/fidelity/theliv/pkg/log"
	"github.com/fidelity/theliv/pkg/service"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const (
	Registered             = "Registered"
	errClusterNameTooShort = "cluster name must be at least 3 characters long"
	errClusterNameInvalid  = "cluster name contains invalid characters"
)

// RegisterAdminPath is the RBAC grant (relative to /theliv-api/v1) that allows
// replacing a cluster registered by another principal, e.g.
// /admin/register/eks-payments or /admin/register/*. It is deliberately not
// under /register so that /register* grants do not imply it.
const RegisterAdminPath = "/admin/register/"

var clusterNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$`)
var accountPattern = regexp.MustCompile(`^[0-9]{12}$`)
var regionPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// Values are written unquoted into TokenTemplate (YAML), so restrict them to
// base64 / JWT / bootstrap-token characters.
var caPattern = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)
var tokenPattern = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)

// Overridable in tests.
var (
	registerCluster  = service.RegisterCluster
	callerPrincipal  = principalFromRequest
	callerCanReplace = func(r *http.Request, cluster string) (bool, error) {
		return authmiddleware.HasGrant(r, RegisterAdminPath+cluster)
	}
)

func principalFromRequest(r *http.Request) (string, error) {
	user, e := authmiddleware.GetUser(r, false)
	if e != nil {
		return "", e
	}
	if user == nil || strings.TrimSpace(user.UID) == "" {
		return "", service.ErrNoPrincipal
	}
	return user.UID, nil
}

func Register(r chi.Router) {
	r.Post("/{cluster}", clusterRegister)
}

// Request body should be in valid Json format, or 400 will be returned.
// Path parameter cluster, should be a valid cluster name (minimum 3 characters).
// If cluster name is less than 3 characters, 400 will be returned.
// Request body should include {"Url": "", "CA": "", "Token": ""}, or 400 will be returned.
// Url must be an https URL (on an allowed host when auth.registerAllowedHosts is set), or 400 is returned.
// If the cluster is already registered by a different principal, 409 is returned unless
// the caller holds the RegisterAdminPath grant for the cluster.
// If backend DB operation failed, return 503.
// if backend DB operation success, return "Registered".
func clusterRegister(w http.ResponseWriter, r *http.Request) {
	cluster := chi.URLParam(r, "cluster")

	var basic service.ClusterBasic
	if err := decodeBody(r.Body, &basic); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	basic.Name = cluster

	l := log.SWithContext(r.Context()).With(
		slog.String("cluster", basic.Name),
		slog.String("clusterUrl", basic.Url),
		slog.String("account", basic.Account),
	)

	// Validate cluster name for security and format compliance
	if validationErr := validateClusterName(basic.Name); validationErr != nil {
		l.With(slog.String("error", validationErr.Error())).Error("cluster name validation failed")
		processError(w, r, err.NewCommonError(r.Context(), err.API, validationErr.Error()))
		return
	}

	// Validate critical fields but only log errors to
	// prevent k8s jobs from retrying failed registrations
	if basic.Url == "" {
		l.Error("cluster URL is empty")
	}

	if basic.CA == "" {
		l.Error("cluster CA is empty")
	}

	if basic.Token == "" {
		l.Error("cluster token is empty")
	}

	if validationErr := validateClusterFields(basic); validationErr != nil {
		l.With(slog.String("error", validationErr.Error())).Error("cluster registration rejected")
		http.Error(w, validationErr.Error(), http.StatusBadRequest)
		return
	}

	principal, pErr := callerPrincipal(r)
	if pErr != nil {
		l.With(slog.String("error", pErr.Error())).Error("unable to identify registering principal")
		http.Error(w, service.ErrNoPrincipal.Error(), http.StatusForbidden)
		return
	}
	l = l.With(slog.String("principal", principal))

	override, gErr := callerCanReplace(r, basic.Name)
	if gErr != nil {
		l.With(slog.String("error", gErr.Error())).Error("failed to check cluster admin grant")
		http.Error(w, SERVICE_UNAVAILABLE, http.StatusServiceUnavailable)
		return
	}

	if regErr := registerCluster(r.Context(), l, basic, principal, override); regErr != nil {
		switch {
		case errors.Is(regErr, service.ErrClusterExists):
			l.Warn("refusing to overwrite cluster registered by another principal")
			http.Error(w, regErr.Error(), http.StatusConflict)
		case errors.Is(regErr, service.ErrNoPrincipal):
			http.Error(w, regErr.Error(), http.StatusForbidden)
		default:
			http.Error(w, SERVICE_UNAVAILABLE, http.StatusServiceUnavailable)
		}
		return
	}
	render.Respond(w, r, Registered)
}

// validateClusterFields rejects values that would redirect Theliv to an
// unintended host or inject content into the generated kubeconfig / basic JSON.
// Empty Url/CA/Token are still only logged (see clusterRegister).
func validateClusterFields(basic service.ClusterBasic) error {
	for field, v := range map[string]string{"URL": basic.Url, "CA": basic.CA, "token": basic.Token} {
		if strings.IndexFunc(v, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) >= 0 {
			return fmt.Errorf("cluster %s must not contain whitespace or control characters", field)
		}
	}
	if basic.CA != "" && !caPattern.MatchString(basic.CA) {
		return fmt.Errorf("cluster CA must be base64 encoded")
	}
	if basic.Token != "" && !tokenPattern.MatchString(basic.Token) {
		return fmt.Errorf("cluster token contains invalid characters")
	}
	if basic.Account != "" && !accountPattern.MatchString(basic.Account) {
		return fmt.Errorf("account must be a 12-digit AWS account id")
	}
	if basic.Region != "" && !regionPattern.MatchString(basic.Region) {
		return fmt.Errorf("region contains invalid characters")
	}
	if basic.Url == "" {
		return nil
	}
	return validateClusterURL(basic.Url, registerAllowedHosts())
}

func registerAllowedHosts() []string {
	if c := config.GetThelivConfig(); c != nil && c.Auth != nil {
		return c.Auth.RegisterAllowedHosts
	}
	return nil
}

func validateClusterURL(raw string, allowedHosts []string) error {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("cluster URL must be an absolute https URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("cluster URL must not contain credentials, query or fragment")
	}
	if len(allowedHosts) == 0 {
		return nil
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, allowed := range allowedHosts {
		allowed = strings.ToLower(strings.Trim(strings.TrimSpace(allowed), "."))
		if allowed != "" && (host == allowed || strings.HasSuffix(host, "."+allowed)) {
			return nil
		}
	}
	return fmt.Errorf("cluster URL host %q is not in the allowed host list", host)
}

// validateClusterName checks for path traversal and validates cluster name format
func validateClusterName(name string) error {
	if len(name) < 3 {
		return fmt.Errorf(errClusterNameTooShort)
	}
	if len(name) > 63 {
		return fmt.Errorf("cluster name must be 63 characters or less")
	}
	// Check for path traversal characters
	if strings.Contains(name, "..") || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return fmt.Errorf(errClusterNameInvalid)
	}
	// Lowercase alphanumeric with hyphens and underscores
	if !clusterNamePattern.MatchString(name) {
		return fmt.Errorf("cluster name must be lowercase alphanumeric with hyphens/underscores, start and end with alphanumeric")
	}
	return nil
}
