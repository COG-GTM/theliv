/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package service

import (
	"context"
	"strings"
	"sync"
	"testing"

	log "github.com/fidelity/theliv/pkg/log"
	"github.com/stretchr/testify/assert"
)

type memClusterStore struct {
	mu   sync.Mutex
	data map[string]string
}

func (m *memClusterStore) Get(_ context.Context, key string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.data[key]; ok {
		return []byte(v), nil
	}
	return nil, nil
}

func (m *memClusterStore) PutAllIf(_ context.Context, absent []string, equal map[string]string, kvs map[string]string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range absent {
		if _, ok := m.data[k]; ok {
			return false, nil
		}
	}
	for k, v := range equal {
		if m.data[k] != v {
			return false, nil
		}
	}
	for k, v := range kvs {
		m.data[k] = v
	}
	return true, nil
}

const (
	testCluster     = "eks-payments"
	testKubeconfKey = KeyPath + "eks/" + testCluster + KubeConfKey
	testOwnerKey    = KeyPath + "eks/" + testCluster + OwnerKey
)

func useMemStore(t *testing.T) *memClusterStore {
	t.Helper()
	m := &memClusterStore{data: map[string]string{}}
	orig := registerStore
	registerStore = m
	t.Cleanup(func() { registerStore = orig })
	return m
}

func register(t *testing.T, url, principal string, override bool) error {
	t.Helper()
	ctx := context.Background()
	basic := ClusterBasic{Name: testCluster, Url: url, CA: "Y2E=", Token: "tok-" + principal}
	return RegisterCluster(ctx, log.SWithContext(ctx), basic, principal, override)
}

func TestRegisterClusterRejectsOverwriteByOtherPrincipal(t *testing.T) {
	m := useMemStore(t)

	assert.NoError(t, register(t, "https://alice.eks.amazonaws.com", "alice", false))
	original := m.data[testKubeconfKey]
	assert.Contains(t, original, "https://alice.eks.amazonaws.com")
	assert.Equal(t, "alice", m.data[testOwnerKey])

	err := register(t, "https://attacker.example.com", "mallory", false)
	assert.ErrorIs(t, err, ErrClusterExists)
	assert.Equal(t, original, m.data[testKubeconfKey])
	assert.Equal(t, "alice", m.data[testOwnerKey])
}

func TestRegisterClusterAllowsOwnerUpdate(t *testing.T) {
	m := useMemStore(t)

	assert.NoError(t, register(t, "https://old.eks.amazonaws.com", "alice", false))
	assert.NoError(t, register(t, "https://new.eks.amazonaws.com", "alice", false))
	assert.Contains(t, m.data[testKubeconfKey], "https://new.eks.amazonaws.com")
	assert.Equal(t, "alice", m.data[testOwnerKey])
}

func TestRegisterClusterAdminOverrideKeepsOwner(t *testing.T) {
	m := useMemStore(t)

	assert.NoError(t, register(t, "https://old.eks.amazonaws.com", "alice", false))
	assert.NoError(t, register(t, "https://new.eks.amazonaws.com", "admin", true))
	assert.Contains(t, m.data[testKubeconfKey], "https://new.eks.amazonaws.com")
	assert.Equal(t, "alice", m.data[testOwnerKey])
}

func TestRegisterClusterLegacyUnownedRequiresOverride(t *testing.T) {
	m := useMemStore(t)
	m.data[testKubeconfKey] = "legacy"

	assert.ErrorIs(t, register(t, "https://x.eks.amazonaws.com", "mallory", false), ErrClusterExists)
	assert.Equal(t, "legacy", m.data[testKubeconfKey])
	_, owned := m.data[testOwnerKey]
	assert.False(t, owned)

	assert.NoError(t, register(t, "https://x.eks.amazonaws.com", "admin", true))
	assert.True(t, strings.Contains(m.data[testKubeconfKey], "https://x.eks.amazonaws.com"))
	assert.Equal(t, "admin", m.data[testOwnerKey])
}

func TestRegisterClusterRequiresPrincipal(t *testing.T) {
	m := useMemStore(t)

	assert.ErrorIs(t, register(t, "https://x.eks.amazonaws.com", "", false), ErrNoPrincipal)
	assert.Empty(t, m.data)
}

// racingStore lets a concurrent first registration commit between the
// override's owner read and its write.
type racingStore struct {
	*memClusterStore
	raced bool
}

func (s *racingStore) PutAllIf(ctx context.Context, absent []string, equal map[string]string, kvs map[string]string) (bool, error) {
	if !s.raced {
		s.raced = true
		s.data[testOwnerKey] = "alice"
		s.data[testKubeconfKey] = "alice-config"
	}
	return s.memClusterStore.PutAllIf(ctx, absent, equal, kvs)
}

func TestRegisterClusterOverrideDoesNotStealConcurrentOwner(t *testing.T) {
	m := useMemStore(t)
	rs := &racingStore{memClusterStore: m}
	registerStore = rs

	assert.NoError(t, register(t, "https://new.eks.amazonaws.com", "admin", true))
	assert.Equal(t, "alice", m.data[testOwnerKey])
	assert.Contains(t, m.data[testKubeconfKey], "https://new.eks.amazonaws.com")
}

func TestRegisterClusterSanitizesDerivedRegion(t *testing.T) {
	m := useMemStore(t)
	ctx := context.Background()
	basic := ClusterBasic{Name: testCluster, Url: `https://a.b.c.d"x.e.f.g`, CA: "Y2E=", Token: "t", Account: "123456789012"}
	assert.NoError(t, RegisterCluster(ctx, log.SWithContext(ctx), basic, "alice", false))
	assert.NotContains(t, m.data[KeyPath+"eks/"+testCluster+BasicKey], `d"x`)
}
