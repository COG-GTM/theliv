/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/fidelity/theliv/pkg/config"
	"github.com/fidelity/theliv/pkg/database/etcd"
	log "github.com/fidelity/theliv/pkg/log"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	KeyPath     = "/theliv/clusters/"
	KubeConfKey = "/kubeconf"
	BasicKey    = "/basic"

	maxTokenLength = 16 * 1024
	maxCALength    = 64 * 1024
)

var (
	// RFC 6750 b64token: covers service account JWTs and EKS "k8s-aws-v1." tokens.
	bearerTokenPattern = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)
	awsAccountPattern  = regexp.MustCompile(`^[0-9]{12}$`)
)

type ClusterBasic struct {
	Url     string
	CA      string
	Name    string
	Token   string
	Account string
	Region  string
}

// ValidateClusterBasic checks the registration fields that end up in the
// stored kubeconfig and basic info. Empty Url/CA/Token are tolerated (and only
// logged by the caller); any non-empty value must be well formed.
func ValidateClusterBasic(basic ClusterBasic) error {
	if basic.Url != "" {
		if err := validateClusterURL(basic.Url); err != nil {
			return err
		}
	}
	if basic.CA != "" {
		if _, err := decodeClusterCA(basic.CA); err != nil {
			return err
		}
	}
	if basic.Token != "" {
		if len(basic.Token) > maxTokenLength || !bearerTokenPattern.MatchString(basic.Token) {
			return errors.New("cluster token must be a bearer token without whitespace")
		}
	}
	if basic.Account != "" && !awsAccountPattern.MatchString(basic.Account) {
		return errors.New("account must be a 12 digit AWS account id")
	}
	return nil
}

func validateClusterURL(raw string) error {
	if strings.ContainsFunc(raw, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return errors.New("cluster URL must not contain whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("cluster URL is not a valid URL")
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("cluster URL must be an https URL with a host and no path, query or credentials")
	}
	return nil
}

// decodeClusterCA returns the PEM bytes of a base64 encoded CA bundle.
func decodeClusterCA(raw string) ([]byte, error) {
	invalid := errors.New("cluster CA must be base64 encoded PEM certificates")
	if len(raw) > maxCALength {
		return nil, invalid
	}
	data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
	if err != nil {
		return nil, invalid
	}
	rest := data
	count := 0
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, invalid
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return nil, invalid
		}
		count++
	}
	if count == 0 || strings.TrimSpace(string(rest)) != "" {
		return nil, invalid
	}
	return data, nil
}

// BuildKubeConfig serializes a token based kubeconfig from validated fields.
func BuildKubeConfig(basic ClusterBasic) ([]byte, error) {
	if err := ValidateClusterBasic(basic); err != nil {
		return nil, err
	}
	cluster := clientcmdapi.NewCluster()
	cluster.Server = basic.Url
	if basic.CA != "" {
		ca, err := decodeClusterCA(basic.CA)
		if err != nil {
			return nil, err
		}
		cluster.CertificateAuthorityData = ca
	}
	user := clientcmdapi.NewAuthInfo()
	user.Token = basic.Token
	kubeContext := clientcmdapi.NewContext()
	kubeContext.Cluster = basic.Name
	kubeContext.AuthInfo = basic.Name

	kubeConfig := clientcmdapi.NewConfig()
	kubeConfig.Clusters[basic.Name] = cluster
	kubeConfig.AuthInfos[basic.Name] = user
	kubeConfig.Contexts[basic.Name] = kubeContext
	kubeConfig.CurrentContext = basic.Name

	value, err := clientcmd.Write(*kubeConfig)
	if err != nil {
		return nil, err
	}
	if err := config.ValidateRegisteredKubeConfig(value); err != nil {
		return nil, err
	}
	return value, nil
}

func buildBasicInfo(basic ClusterBasic) ([]byte, error) {
	return json.Marshal(config.ClusterBasicInfo{
		Provider: "aws",
		Account:  basic.Account,
		Role:     fmt.Sprintf("arn:aws:iam::%s:role/EKS_Theliv", basic.Account),
		Name:     basic.Name,
		Region:   basic.Region,
	})
}

// Insert or update 1 record, to /theliv/clusters/{name}/kubeconf.
func RegisterCluster(ctx context.Context, l *log.SugaredSlogLogger, basic ClusterBasic) error {
	clusterType := basic.Name[:3]
	etcdBaseKey := KeyPath + clusterType + "/" + basic.Name

	l.Info("Registering cluster with Theliv")

	value, err := BuildKubeConfig(basic)
	if err != nil {
		return err
	}

	// if aws account id present, convert to json and insert in db
	if basic.Account != "" {
		l.Info("AWS account provided, persisting to db")
		if urlSlice := strings.Split(basic.Url, "."); len(urlSlice) > 5 {
			basic.Region = urlSlice[len(urlSlice)-4]
		}

		basicJson, err := buildBasicInfo(basic)
		if err != nil {
			return err
		}

		if err := etcd.PutStr(etcdBaseKey+BasicKey, string(basicJson)); err != nil {
			return err
		}
	}

	return etcd.PutStr(etcdBaseKey+KubeConfKey, string(value))
}
