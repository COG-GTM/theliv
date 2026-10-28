/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

const baseKubeConfig = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: Zm9v
    server: https://example.com
CLUSTER_EXTRA  name: c1
contexts:
- context:
    cluster: c1
    user: c1
  name: c1
current-context: c1
kind: Config
users:
- name: c1
  user:
    token: abc
USER_EXTRA`

func kubeConfig(clusterExtra, userExtra string) []byte {
	s := strings.Replace(baseKubeConfig, "CLUSTER_EXTRA", clusterExtra, 1)
	return []byte(strings.Replace(s, "USER_EXTRA", userExtra, 1))
}

func TestValidateRegisteredKubeConfig(t *testing.T) {
	assert.NoError(t, ValidateRegisteredKubeConfig(kubeConfig("", "")))

	rejected := map[string][]byte{
		"exec": kubeConfig("", `    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: /bin/sh
      args: ["-c", "id"]
`),
		"tokenFile":        kubeConfig("", "    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token\n"),
		"auth-provider":    kubeConfig("", "    auth-provider:\n      name: oidc\n"),
		"client-cert file": kubeConfig("", "    client-certificate: /etc/theliv/etcd.crt\n"),
		"client-key file":  kubeConfig("", "    client-key: /etc/theliv/etcd.key\n"),
		"basic auth":       kubeConfig("", "    username: admin\n    password: admin\n"),
		"impersonate":      kubeConfig("", "    as: system:admin\n"),
		"ca file":          kubeConfig("    certificate-authority: /etc/theliv/ca.crt\n", ""),
		"insecure":         kubeConfig("    insecure-skip-tls-verify: true\n", ""),
		"proxy-url":        kubeConfig("    proxy-url: http://attacker.example\n", ""),
		"tls-server-name":  kubeConfig("    tls-server-name: internal.example\n", ""),
		"not yaml":         []byte("{{{"),
		"no users":         []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: c1\n  cluster:\n    server: https://example.com\n"),
	}
	for name, kc := range rejected {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, ValidateRegisteredKubeConfig(kc))
		})
	}
}
