/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package config

import (
	"errors"
	"fmt"

	"k8s.io/client-go/tools/clientcmd"
)

// ValidateRegisteredKubeConfig rejects kubeconfigs that use anything beyond a
// server URL, inline CA data and a static bearer token. Kubeconfigs stored by
// cluster registration never need more, and features such as exec plugins,
// auth providers, tokenFile or local file references would let a registrant
// run commands on, or read files from, the theliv server.
func ValidateRegisteredKubeConfig(kubeconf []byte) error {
	cfg, err := clientcmd.Load(kubeconf)
	if err != nil {
		return fmt.Errorf("invalid kubeconfig: %w", err)
	}
	if len(cfg.Clusters) == 0 || len(cfg.AuthInfos) == 0 {
		return errors.New("kubeconfig must define a cluster and a user")
	}
	for name, c := range cfg.Clusters {
		switch {
		case c.CertificateAuthority != "":
			return fmt.Errorf("cluster %q: certificate-authority file is not allowed", name)
		case c.InsecureSkipTLSVerify:
			return fmt.Errorf("cluster %q: insecure-skip-tls-verify is not allowed", name)
		case c.ProxyURL != "":
			return fmt.Errorf("cluster %q: proxy-url is not allowed", name)
		case c.TLSServerName != "":
			return fmt.Errorf("cluster %q: tls-server-name is not allowed", name)
		case len(c.Extensions) > 0:
			return fmt.Errorf("cluster %q: extensions are not allowed", name)
		}
	}
	for name, a := range cfg.AuthInfos {
		switch {
		case a.Exec != nil:
			return fmt.Errorf("user %q: exec credential plugins are not allowed", name)
		case a.AuthProvider != nil:
			return fmt.Errorf("user %q: auth-provider is not allowed", name)
		case a.TokenFile != "":
			return fmt.Errorf("user %q: tokenFile is not allowed", name)
		case a.ClientCertificate != "" || a.ClientKey != "":
			return fmt.Errorf("user %q: client certificate/key files are not allowed", name)
		case len(a.ClientCertificateData) > 0 || len(a.ClientKeyData) > 0:
			return fmt.Errorf("user %q: client certificates are not allowed", name)
		case a.Username != "" || a.Password != "":
			return fmt.Errorf("user %q: basic auth is not allowed", name)
		case a.Impersonate != "" || a.ImpersonateUID != "" || len(a.ImpersonateGroups) > 0 || len(a.ImpersonateUserExtra) > 0:
			return fmt.Errorf("user %q: impersonation is not allowed", name)
		case len(a.Extensions) > 0:
			return fmt.Errorf("user %q: extensions are not allowed", name)
		}
	}
	return nil
}
