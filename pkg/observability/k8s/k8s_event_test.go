/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package k8s

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/fidelity/theliv/pkg/config"
	"github.com/fidelity/theliv/pkg/kubeclient"
	"github.com/fidelity/theliv/pkg/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	restclient "k8s.io/client-go/rest"
)

// fakeAPIServer serves just enough discovery and an events list for namespace "shop".
func fakeAPIServer(t *testing.T, failFirstLists int32) (*httptest.Server, *int32) {
	var lists int32
	events := v1.EventList{TypeMeta: metav1.TypeMeta{Kind: "EventList", APIVersion: "v1"}}
	for _, e := range []struct{ name, obj, msg string }{
		{"e1", "web-1", "Back-off restarting failed container"},
		{"e2", "web-2", "Pulled image"},
		{"e3", "db-0", "Readiness probe failed for web-1"},
		{"e4", "cache-0", "Started container"},
	} {
		events.Items = append(events.Items, v1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: e.name, Namespace: "shop", UID: types.UID("uid-" + e.name)},
			InvolvedObject: v1.ObjectReference{Kind: "Pod", Name: e.obj, Namespace: "shop"},
			Message:        e.msg,
		})
	}
	write := func(w http.ResponseWriter, v interface{}) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api":
			write(w, metav1.APIVersions{TypeMeta: metav1.TypeMeta{Kind: "APIVersions"}, Versions: []string{"v1"}})
		case "/apis":
			write(w, metav1.APIGroupList{TypeMeta: metav1.TypeMeta{Kind: "APIGroupList", APIVersion: "v1"}})
		case "/api/v1":
			write(w, metav1.APIResourceList{TypeMeta: metav1.TypeMeta{Kind: "APIResourceList", APIVersion: "v1"},
				GroupVersion: "v1",
				APIResources: []metav1.APIResource{{Name: "events", Namespaced: true, Kind: "Event", Verbs: []string{"list"}}}})
		case "/api/v1/namespaces/shop/events":
			if n := atomic.AddInt32(&lists, 1); n <= failFirstLists {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			write(w, events)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &lists
}

func newTestRetriever(t *testing.T, host string) K8sEventRetriever {
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "k8s"), 0o755))
	cfgFile := filepath.Join(dir, "theliv.yaml")
	require.NoError(t, os.WriteFile(cfgFile, []byte("port: 8080\n"), 0o644))
	config.NewFileConfigLoader(cfgFile).LoadConfigs()

	client, err := kubeclient.NewKubeClient(context.Background(), &restclient.Config{Host: host})
	require.NoError(t, err)
	return NewK8sEventRetriever(client)
}

func eventIDs(records []observability.EventRecord) []string {
	ids := make([]string, 0, len(records))
	for _, r := range records {
		ids = append(ids, r.EventId)
	}
	sort.Strings(ids)
	return ids
}

func getEvents(t *testing.T, r K8sEventRetriever, name string) []observability.EventRecord {
	records, err := r.Retrieve(observability.EventFilterCriteria{FilterCriteria: r.AddFilters(name, "shop")}).GetEvents(context.Background())
	require.NoError(t, err)
	return records
}

func TestGetEventsSharesOneListPerRetriever(t *testing.T) {
	srv, lists := fakeAPIServer(t, 0)
	r := newTestRetriever(t, srv.URL)

	want := map[string][]string{
		"web-1":   {"uid-e1", "uid-e3"},
		"web-2":   {"uid-e2"},
		"cache-0": {"uid-e4"},
		"":        {"uid-e1", "uid-e2", "uid-e3", "uid-e4"},
	}
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		for name, ids := range want {
			wg.Add(1)
			go func(name string, ids []string) {
				defer wg.Done()
				assert.Equal(t, ids, eventIDs(getEvents(t, r, name)), "name %q", name)
			}(name, ids)
		}
	}
	wg.Wait()
	assert.EqualValues(t, 1, atomic.LoadInt32(lists))

	// A new retriever (a new request) lists again.
	r2 := NewK8sEventRetriever(r.kubeclient)
	getEvents(t, r2, "web-1")
	assert.EqualValues(t, 2, atomic.LoadInt32(lists))
}

func TestGetEventsRetriesAfterFailedList(t *testing.T) {
	srv, lists := fakeAPIServer(t, 1)
	r := newTestRetriever(t, srv.URL)

	assert.Empty(t, getEvents(t, r, "web-1"))
	assert.Equal(t, []string{"uid-e1", "uid-e3"}, eventIDs(getEvents(t, r, "web-1")))
	assert.Equal(t, []string{"uid-e2"}, eventIDs(getEvents(t, r, "web-2")))
	assert.EqualValues(t, 2, atomic.LoadInt32(lists))
}

func TestGetEventsZeroValueRetrieverListsEachCall(t *testing.T) {
	srv, lists := fakeAPIServer(t, 0)
	r := K8sEventRetriever{kubeclient: newTestRetriever(t, srv.URL).kubeclient}

	assert.Equal(t, []string{"uid-e1", "uid-e3"}, eventIDs(getEvents(t, r, "web-1")))
	assert.Equal(t, []string{"uid-e2"}, eventIDs(getEvents(t, r, "web-2")))
	assert.EqualValues(t, 2, atomic.LoadInt32(lists))
}
