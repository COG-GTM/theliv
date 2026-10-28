/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"context"
	"errors"
	"regexp"
	"strings"

	invest "github.com/fidelity/theliv/internal/investigators"
	"github.com/fidelity/theliv/pkg/database/etcd"
	log "github.com/fidelity/theliv/pkg/log"
)

const (
	KeyPath     = "/theliv/clusters/"
	KubeConfKey = "/kubeconf"
	BasicKey    = "/basic"
	OwnerKey    = "/owner"

	TokenTemplate = `apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: {{.CA}}
    server: {{.Url}}
  name: {{.Name}}
contexts:
- context:
    cluster: {{.Name}}
    user: {{.Name}}
  name: {{.Name}}
current-context: {{.Name}}
kind: Config
preferences: {}
users:
- name: {{.Name}}
  user:
    token: {{.Token}}`

	BasicTemplate = `{
	"provider": "aws",
	"account": "{{.Account}}",
	"role": "arn:aws:iam::{{.Account}}:role/EKS_Theliv",
	"name": "{{.Name}}",
	"region": "{{.Region}}"
}`
)

var (
	// ErrClusterExists is returned when the cluster is already registered and
	// the caller is neither its recorded owner nor allowed to override it.
	ErrClusterExists = errors.New("cluster is already registered by another principal")
	// ErrNoPrincipal is returned when the caller identity is unknown.
	ErrNoPrincipal = errors.New("registering principal is unknown")
)

var regionPattern = regexp.MustCompile(`^[a-z0-9-]*$`)

type ClusterBasic struct {
	Url     string
	CA      string
	Name    string
	Token   string
	Account string
	Region  string
}

// clusterStore is the subset of etcd used for cluster registration.
type clusterStore interface {
	Get(ctx context.Context, key string) ([]byte, error)
	PutAllIf(ctx context.Context, absent []string, equal map[string]string, kvs map[string]string) (bool, error)
}

type etcdClusterStore struct{}

func (etcdClusterStore) Get(ctx context.Context, key string) ([]byte, error) {
	return etcd.Get(ctx, key)
}

func (etcdClusterStore) PutAllIf(ctx context.Context, absent []string, equal map[string]string, kvs map[string]string) (bool, error) {
	return etcd.PutAllIf(ctx, absent, equal, kvs)
}

var registerStore clusterStore = etcdClusterStore{}

// RegisterCluster writes /theliv/clusters/{type}/{name}/kubeconf (and /basic) for
// the given principal. A new cluster is recorded as owned by principal. An
// existing cluster may only be replaced by its recorded owner, or when override
// is true (admin grant); otherwise ErrClusterExists is returned and nothing is
// written. Clusters registered before ownership was recorded have no owner and
// can only be replaced with override.
func RegisterCluster(ctx context.Context, l *log.SugaredSlogLogger, basic ClusterBasic, principal string, override bool) error {
	if principal == "" {
		return ErrNoPrincipal
	}
	clusterType := basic.Name[:3]
	etcdBaseKey := KeyPath + clusterType + "/" + basic.Name
	kubeconfKey := etcdBaseKey + KubeConfKey
	ownerKey := etcdBaseKey + OwnerKey

	l.Info("Registering cluster with Theliv")

	kvs := map[string]string{}

	// if aws account id present, convert to json and insert in db
	if basic.Account != "" {
		l.Info("AWS account provided, persisting to db")
		if urlSlice := strings.Split(basic.Url, "."); len(urlSlice) > 5 {
			basic.Region = urlSlice[len(urlSlice)-4]
		}
		if !regionPattern.MatchString(basic.Region) {
			basic.Region = ""
		}

		basicJson, err := invest.ExecGoTemplate(ctx, BasicTemplate, basic)
		if err != nil {
			return err
		}
		kvs[etcdBaseKey+BasicKey] = basicJson
	}

	value, err := invest.ExecGoTemplate(ctx, TokenTemplate, basic)
	if err != nil {
		return err
	}
	kvs[kubeconfKey] = value

	// Retry only covers an override racing a concurrent first registration.
	for attempt := 0; attempt < 3; attempt++ {
		owner, err := registerStore.Get(ctx, ownerKey)
		if err != nil {
			return err
		}

		var absent []string
		var equal map[string]string
		switch {
		case owner == nil && !override:
			// New cluster: only succeeds if nothing is registered under this name.
			absent = []string{ownerKey, kubeconfKey}
			kvs[ownerKey] = principal
		case owner == nil:
			// Override of an unowned (legacy) cluster.
			absent = []string{ownerKey}
			kvs[ownerKey] = principal
		case string(owner) == principal || override:
			// Keep the recorded owner; guard against a concurrent ownership change.
			equal = map[string]string{ownerKey: string(owner)}
			delete(kvs, ownerKey)
		default:
			return ErrClusterExists
		}

		ok, err := registerStore.PutAllIf(ctx, absent, equal, kvs)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !override {
			return ErrClusterExists
		}
	}
	return ErrClusterExists
}
