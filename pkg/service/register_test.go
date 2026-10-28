/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/fidelity/theliv/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

const execInjection = "\n    exec:\n      apiVersion: client.authentication.k8s.io/v1beta1\n      command: /bin/sh\n      args: [\"-c\", \"id > /tmp/pwned\"]"

func testCA(t *testing.T) (string, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kubernetes"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return base64.StdEncoding.EncodeToString(pemBytes), pemBytes
}

func validBasic(t *testing.T) ClusterBasic {
	ca, _ := testCA(t)
	return ClusterBasic{
		Name:  "eks-prod",
		Url:   "https://ABCDEF0123456789.gr7.us-east-1.eks.amazonaws.com",
		CA:    ca,
		Token: "k8s-aws-v1.aHR0cHM6Ly9zdHMuYW1hem9uYXdzLmNvbS8_QWN0aW9uPUdldENhbGxlcklkZW50aXR5",
	}
}

func TestValidateClusterBasic(t *testing.T) {
	ca, _ := testCA(t)
	keyPEM := base64.StdEncoding.EncodeToString(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
	tests := []struct {
		name    string
		mutate  func(b *ClusterBasic)
		wantErr bool
	}{
		{"valid", func(b *ClusterBasic) {}, false},
		{"valid jwt token", func(b *ClusterBasic) { b.Token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln-_" }, false},
		{"valid url with port and slash", func(b *ClusterBasic) { b.Url = "https://10.0.0.1:6443/" }, false},
		{"valid wrapped CA", func(b *ClusterBasic) { b.CA = ca[:40] + "\n" + ca[40:] }, false},
		{"valid account", func(b *ClusterBasic) { b.Account = "123456789012" }, false},
		{"empty fields tolerated", func(b *ClusterBasic) { b.Url, b.CA, b.Token = "", "", "" }, false},

		{"token exec injection", func(b *ClusterBasic) { b.Token = execInjection }, true},
		{"token tokenFile injection", func(b *ClusterBasic) {
			b.Token = "x\n    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token"
		}, true},
		{"token with space", func(b *ClusterBasic) { b.Token = "abc def" }, true},
		{"token too long", func(b *ClusterBasic) { b.Token = string(make([]byte, maxTokenLength+1)) }, true},
		{"url newline injection", func(b *ClusterBasic) { b.Url = "https://attacker.example\n    insecure-skip-tls-verify: true" }, true},
		{"url http", func(b *ClusterBasic) { b.Url = "http://attacker.example" }, true},
		{"url no host", func(b *ClusterBasic) { b.Url = "https:///path" }, true},
		{"url with path", func(b *ClusterBasic) { b.Url = "https://attacker.example/api" }, true},
		{"url with query", func(b *ClusterBasic) { b.Url = "https://attacker.example?x=1" }, true},
		{"url with userinfo", func(b *ClusterBasic) { b.Url = "https://u:p@attacker.example" }, true},
		{"ca newline injection", func(b *ClusterBasic) { b.CA = "Zm9v\n    proxy-url: http://attacker.example" }, true},
		{"ca not base64", func(b *ClusterBasic) { b.CA = "not-base64!" }, true},
		{"ca not pem", func(b *ClusterBasic) { b.CA = base64.StdEncoding.EncodeToString([]byte("hello")) }, true},
		{"ca not certificate", func(b *ClusterBasic) { b.CA = keyPEM }, true},
		{"account json injection", func(b *ClusterBasic) { b.Account = `1", "provider": "x` }, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := validBasic(t)
			tt.mutate(&b)
			err := ValidateClusterBasic(b)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestBuildKubeConfig(t *testing.T) {
	b := validBasic(t)
	_, caPEM := testCA(t)
	b.CA = base64.StdEncoding.EncodeToString(caPEM)

	value, err := BuildKubeConfig(b)
	require.NoError(t, err)
	require.NoError(t, config.ValidateRegisteredKubeConfig(value))

	rc, err := clientcmd.RESTConfigFromKubeConfig(value)
	require.NoError(t, err)
	assert.Equal(t, b.Url, rc.Host)
	assert.Equal(t, b.Token, rc.BearerToken)
	assert.Equal(t, caPEM, rc.TLSClientConfig.CAData)
	assert.Nil(t, rc.ExecProvider)
	assert.Nil(t, rc.AuthProvider)
	assert.Empty(t, rc.BearerTokenFile)

	raw, err := clientcmd.Load(value)
	require.NoError(t, err)
	assert.Equal(t, "eks-prod", raw.CurrentContext)
}

func TestBuildKubeConfigRejectsInjection(t *testing.T) {
	for _, mutate := range []func(b *ClusterBasic){
		func(b *ClusterBasic) { b.Token = execInjection },
		func(b *ClusterBasic) { b.Url = "https://attacker.example" + execInjection },
		func(b *ClusterBasic) { b.CA = "Zm9v" + execInjection },
	} {
		b := validBasic(t)
		mutate(&b)
		value, err := BuildKubeConfig(b)
		assert.Error(t, err)
		assert.Nil(t, value)
	}
}

func TestBuildBasicInfo(t *testing.T) {
	b := validBasic(t)
	b.Account = "123456789012"
	b.Region = "us-east-1"
	raw, err := buildBasicInfo(b)
	require.NoError(t, err)
	var got map[string]string
	require.NoError(t, json.Unmarshal(raw, &got))
	assert.Equal(t, map[string]string{
		"provider": "aws",
		"account":  "123456789012",
		"role":     "arn:aws:iam::123456789012:role/EKS_Theliv",
		"name":     "eks-prod",
		"region":   "us-east-1",
	}, got)
}
