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
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

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

var (
	clusterNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?$`)
	dnsLabelPattern    = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	tldPattern         = regexp.MustCompile(`^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

func Register(r chi.Router) {
	r.Post("/{cluster}", clusterRegister)
}

// Request body should be in valid Json format, or 400 will be returned.
// Path parameter cluster, should be a valid cluster name (minimum 3 characters).
// If cluster name is less than 3 characters, 400 will be returned.
// Request body should include {"Url": "", "CA": "", "Token": ""}, or 400 will be returned.
// Url must be https://<hostname>[:port] (no IP literals), and must match
// ThelivConfig.ClusterUrlAllowedDomains when configured, or 400 will be returned.
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

	// The URL is dialed by the Theliv server on every detection, so reject
	// anything that is not a public-style cluster API endpoint.
	if urlErr := validateClusterURL(basic.Url, allowedClusterDomains()); urlErr != nil {
		l.With(slog.String("error", urlErr.Error())).Error("cluster URL validation failed")
		http.Error(w, urlErr.Error(), http.StatusBadRequest)
		return
	}

	// Validate remaining fields but only log errors to
	// prevent k8s jobs from retrying failed registrations

	if basic.CA == "" {
		l.Error("cluster CA is empty")
	}

	if basic.Token == "" {
		l.Error("cluster token is empty")
	}

	if err := service.RegisterCluster(r.Context(), l, basic); err != nil {
		http.Error(w, SERVICE_UNAVAILABLE, http.StatusServiceUnavailable)
		return
	}
	render.Respond(w, r, Registered)
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

func allowedClusterDomains() []string {
	if c := config.GetThelivConfig(); c != nil {
		return c.ClusterUrlAllowedDomains
	}
	return nil
}

// validateClusterURL only accepts https://<hostname>[:port] where hostname is a
// fully qualified DNS name (no IP literals, no localhost), optionally restricted
// to allowedDomains (exact match or subdomain).
func validateClusterURL(raw string, allowedDomains []string) error {
	if raw == "" {
		return errors.New("cluster URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("cluster URL is not a valid URL")
	}
	if u.Scheme != "https" {
		return errors.New("cluster URL must use https")
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return errors.New("cluster URL must be in the form https://<hostname>[:port]")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return errors.New("cluster URL port is invalid")
		}
	}

	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	if host == "" {
		return errors.New("cluster URL must include a hostname")
	}
	if net.ParseIP(host) != nil || strings.Contains(host, ":") {
		return errors.New("cluster URL must use a hostname, not an IP address")
	}
	if len(host) > 253 {
		return errors.New("cluster URL hostname is too long")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("cluster URL hostname must be a fully qualified domain name")
	}
	for _, label := range labels {
		if !dnsLabelPattern.MatchString(label) {
			return errors.New("cluster URL hostname is invalid")
		}
	}
	if !tldPattern.MatchString(labels[len(labels)-1]) {
		return errors.New("cluster URL must use a hostname, not an IP address")
	}
	if labels[len(labels)-1] == "localhost" {
		return errors.New("cluster URL must not point to localhost")
	}

	if len(allowedDomains) == 0 {
		return nil
	}
	for _, d := range allowedDomains {
		d = strings.ToLower(strings.TrimSuffix(strings.TrimLeft(strings.TrimPrefix(strings.TrimSpace(d), "*"), "."), "."))
		if d != "" && (host == d || strings.HasSuffix(host, "."+d)) {
			return nil
		}
	}
	return errors.New("cluster URL hostname is not in the allowed cluster domains")
}
