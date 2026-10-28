/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fidelity/theliv/internal/rbac"
	"github.com/go-chi/chi/v5"
)

type fakeFeedbackStore struct {
	count int64
	puts  []string
	ttls  []time.Duration
	data  []FeebackData
}

func setupFeedback(t *testing.T, user *rbac.User) (*fakeFeedbackStore, *time.Time, http.Handler) {
	t.Helper()
	store := &fakeFeedbackStore{}
	now := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

	origNow, origUser, origCount, origPut, origLimiter := feedbackNow, feedbackUser, countFeedbacks, putFeedback, feedbackLimiter
	t.Cleanup(func() {
		feedbackNow, feedbackUser, countFeedbacks, putFeedback, feedbackLimiter = origNow, origUser, origCount, origPut, origLimiter
	})

	feedbackNow = func() time.Time { return now }
	feedbackUser = func(r *http.Request, getAds bool) (*rbac.User, error) {
		if user == nil {
			return nil, errors.New("no user")
		}
		return user, nil
	}
	countFeedbacks = func(ctx context.Context, prefix string) (int64, error) {
		if prefix != feedbackKeyPrefix {
			t.Fatalf("unexpected prefix %q", prefix)
		}
		return store.count, nil
	}
	putFeedback = func(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
		store.puts = append(store.puts, key)
		store.ttls = append(store.ttls, ttl)
		store.data = append(store.data, value.(FeebackData))
		store.count++
		return nil
	}
	feedbackLimiter = newSubmissionLimiter(feedbackInterval)

	r := chi.NewRouter()
	r.Route("/feedbacks", SubmitFeedback)
	return store, &now, r
}

func postFeedback(h http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/feedbacks/", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func feedbackBody(msg string) string {
	b, _ := json.Marshal(Feedback{Message: msg})
	return string(b)
}

func TestSubmitFeedbackStoresWithTTL(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "alice"})

	rec := postFeedback(h, feedbackBody("great tool"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(store.puts) != 1 || store.puts[0] != "/theliv/feedbacks/leased/20261028120000" {
		t.Fatalf("puts = %v", store.puts)
	}
	if store.ttls[0] != feedbackTTL {
		t.Fatalf("ttl = %v", store.ttls[0])
	}
	if store.data[0].Message != "great tool" || store.data[0].User.UID != "alice" {
		t.Fatalf("data = %+v", store.data[0])
	}
}

func TestSubmitFeedbackRejectsOversizedBody(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "mallory"})

	rec := postFeedback(h, feedbackBody(strings.Repeat("a", 100<<10)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if len(store.puts) != 0 {
		t.Fatalf("oversized feedback was stored")
	}
}

func TestSubmitFeedbackRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"malformed json", `{"message":`},
		{"trailing data", `{"message":"hi"}{"message":"again"}`},
		{"not an object", `"hello"`},
		{"empty message", `{"message":""}`},
		{"blank message", `{"message":"   "}`},
		{"too long message", feedbackBody(strings.Repeat("a", maxFeedbackMessageLen+1))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store, _, h := setupFeedback(t, &rbac.User{UID: "mallory"})
			rec := postFeedback(h, tt.body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if len(store.puts) != 0 {
				t.Fatalf("invalid feedback was stored")
			}
		})
	}
}

func TestSubmitFeedbackAcceptsMaxLengthMultibyteMessage(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "alice"})

	rec := postFeedback(h, feedbackBody(strings.Repeat("é", maxFeedbackMessageLen)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	if len(store.puts) != 1 {
		t.Fatalf("puts = %v", store.puts)
	}
}

func TestSubmitFeedbackRequiresUser(t *testing.T) {
	store, _, h := setupFeedback(t, nil)

	rec := postFeedback(h, feedbackBody("hi"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if len(store.puts) != 0 {
		t.Fatalf("anonymous feedback was stored")
	}
}

func TestSubmitFeedbackRateLimitsPerUser(t *testing.T) {
	store, now, h := setupFeedback(t, &rbac.User{UID: "mallory"})

	if rec := postFeedback(h, feedbackBody("first")); rec.Code != http.StatusOK {
		t.Fatalf("first status = %d", rec.Code)
	}
	*now = now.Add(30 * time.Second)
	rec := postFeedback(h, feedbackBody("second"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second status = %d, want 429", rec.Code)
	}
	if rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	*now = now.Add(31 * time.Second)
	if rec := postFeedback(h, feedbackBody("third")); rec.Code != http.StatusOK {
		t.Fatalf("third status = %d", rec.Code)
	}
	if len(store.puts) != 2 {
		t.Fatalf("puts = %v", store.puts)
	}
}

func TestSubmitFeedbackRateLimitIsPerUser(t *testing.T) {
	user := &rbac.User{UID: "alice"}
	store, _, h := setupFeedback(t, user)

	if rec := postFeedback(h, feedbackBody("from alice")); rec.Code != http.StatusOK {
		t.Fatalf("alice status = %d", rec.Code)
	}
	user.UID = "bob"
	if rec := postFeedback(h, feedbackBody("from bob")); rec.Code != http.StatusOK {
		t.Fatalf("bob status = %d", rec.Code)
	}
	if len(store.puts) != 2 {
		t.Fatalf("puts = %v", store.puts)
	}
}

func TestSubmitFeedbackRejectsWhenStoreFull(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "alice"})
	store.count = maxStoredFeedbacks

	rec := postFeedback(h, feedbackBody("hi"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if len(store.puts) != 0 {
		t.Fatalf("feedback stored past the cap")
	}
}

func TestSubmitFeedbackStoreErrorDoesNotReportSuccess(t *testing.T) {
	_, _, h := setupFeedback(t, &rbac.User{UID: "alice"})
	putFeedback = func(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
		return errors.New("etcdserver: mvcc: database space exceeded")
	}

	rec := postFeedback(h, feedbackBody("hi"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "Feedback received.") {
		t.Fatalf("success reported after store error: %s", rec.Body.String())
	}
}

func TestSubmitFeedbackRejectsOversizedTrailingData(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "mallory"})

	rec := postFeedback(h, `{"message":"hi"}`+strings.Repeat(" ", 100<<10))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	if len(store.puts) != 0 {
		t.Fatalf("oversized feedback was stored")
	}
}

func TestSubmitFeedbackCountsOnlyLeasedPrefix(t *testing.T) {
	if !strings.HasPrefix(feedbackKeyPrefix, "/theliv/feedbacks/") || feedbackKeyPrefix == "/theliv/feedbacks/" {
		t.Fatalf("feedbackKeyPrefix %q must be a sub-prefix of /theliv/feedbacks/", feedbackKeyPrefix)
	}
	legacyKey := "/theliv/feedbacks/20240101000000"
	if strings.HasPrefix(legacyKey, feedbackKeyPrefix) {
		t.Fatalf("legacy key %q would be counted under %q", legacyKey, feedbackKeyPrefix)
	}
}

func TestSubmitFeedbackStoreErrorReleasesRateLimit(t *testing.T) {
	store, now, h := setupFeedback(t, &rbac.User{UID: "alice"})
	ok := putFeedback
	putFeedback = func(ctx context.Context, key string, value interface{}, ttl time.Duration) error {
		return errors.New("etcdserver: request timed out")
	}
	if rec := postFeedback(h, feedbackBody("hi")); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	putFeedback = ok
	*now = now.Add(time.Second)
	if rec := postFeedback(h, feedbackBody("hi")); rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", rec.Code)
	}
	if len(store.puts) != 1 {
		t.Fatalf("puts = %v", store.puts)
	}
}

func TestSubmitFeedbackCountErrorReleasesRateLimit(t *testing.T) {
	store, _, h := setupFeedback(t, &rbac.User{UID: "alice"})
	ok := countFeedbacks
	countFeedbacks = func(ctx context.Context, prefix string) (int64, error) {
		return 0, errors.New("etcdserver: request timed out")
	}
	if rec := postFeedback(h, feedbackBody("hi")); rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}

	countFeedbacks = ok
	if rec := postFeedback(h, feedbackBody("hi")); rec.Code != http.StatusOK {
		t.Fatalf("retry status = %d, want 200", rec.Code)
	}
	if len(store.puts) != 1 {
		t.Fatalf("puts = %v", store.puts)
	}
}

func TestSubmissionLimiterReleaseKeepsNewerReservation(t *testing.T) {
	l := newSubmissionLimiter(time.Minute)
	t0 := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	if !l.allow("u", t0) {
		t.Fatal("first allow failed")
	}
	l.release("u", t0.Add(-time.Hour))
	if l.allow("u", t0.Add(time.Second)) {
		t.Fatal("release with a stale timestamp freed the current reservation")
	}
}
