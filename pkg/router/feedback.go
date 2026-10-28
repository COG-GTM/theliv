/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fidelity/theliv/internal/rbac"
	"github.com/fidelity/theliv/pkg/auth/authmiddleware"
	"github.com/fidelity/theliv/pkg/database/etcd"
	theliverr "github.com/fidelity/theliv/pkg/err"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const (
	// Leased entries live under their own sub-prefix so that legacy, unleased
	// keys directly under /theliv/feedbacks/ never count toward the cap.
	feedbackKeyPrefix = "/theliv/feedbacks/leased/"

	maxFeedbackBodyBytes  = 16 << 10
	maxFeedbackMessageLen = 2000
	maxStoredFeedbacks    = 5000
	feedbackTTL           = 90 * 24 * time.Hour
	feedbackInterval      = time.Minute
)

type FeebackData struct {
	User    *rbac.User `json:"user,omitempty"`
	Time    time.Time  `json:"time"`
	Message string     `json:"message"`
}
type Feedback struct {
	Message string `json:"message"`
}

var (
	feedbackNow     = time.Now
	feedbackUser    = authmiddleware.GetUser
	countFeedbacks  = etcd.CountWithPrefix
	putFeedback     = etcd.PutWithTTL
	feedbackLimiter = newSubmissionLimiter(feedbackInterval)
)

func SubmitFeedback(r chi.Router) {
	r.Post("/", func(w http.ResponseWriter, r *http.Request) {
		user, err := feedbackUser(r, false)
		if err != nil || user == nil {
			feedbackError(w, r, http.StatusUnauthorized, "unable to identify the current user")
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxFeedbackBodyBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				feedbackError(w, r, http.StatusRequestEntityTooLarge,
					fmt.Sprintf("request body must not exceed %d bytes", maxFeedbackBodyBytes))
				return
			}
			feedbackError(w, r, http.StatusBadRequest, "unable to read request body")
			return
		}
		var d Feedback
		if err := json.Unmarshal(body, &d); err != nil {
			feedbackError(w, r, http.StatusBadRequest, "request body must be a JSON object with a message")
			return
		}
		if strings.TrimSpace(d.Message) == "" {
			feedbackError(w, r, http.StatusBadRequest, "message must not be empty")
			return
		}
		if utf8.RuneCountInString(d.Message) > maxFeedbackMessageLen {
			feedbackError(w, r, http.StatusBadRequest,
				fmt.Sprintf("message must not exceed %d characters", maxFeedbackMessageLen))
			return
		}

		currentTime := feedbackNow()
		limitKey := userKey(user)
		if !feedbackLimiter.allow(limitKey, currentTime) {
			w.Header().Set("Retry-After", strconv.Itoa(int(feedbackInterval/time.Second)))
			feedbackError(w, r, http.StatusTooManyRequests, "only one feedback submission per minute is allowed")
			return
		}

		stored, err := countFeedbacks(r.Context(), feedbackKeyPrefix)
		if err != nil {
			feedbackLimiter.release(limitKey, currentTime)
			processError(w, r, err)
			return
		}
		if stored >= maxStoredFeedbacks {
			feedbackError(w, r, http.StatusServiceUnavailable, "feedback storage is full, please try again later")
			return
		}

		key := feedbackKeyPrefix + getTimeStr(currentTime)
		data := FeebackData{
			User:    user,
			Time:    currentTime,
			Message: d.Message,
		}
		if err := putFeedback(r.Context(), key, data, feedbackTTL); err != nil {
			feedbackLimiter.release(limitKey, currentTime)
			processError(w, r, err)
			return
		}
		render.JSON(w, r, "Feedback received.")
	})

}

func feedbackError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	w.WriteHeader(status)
	render.JSON(w, r, theliverr.CommonError{Kind: theliverr.API, Message: msg})
}

func userKey(user *rbac.User) string {
	switch {
	case user.UID != "":
		return "uid:" + user.UID
	case user.Emailaddress != "":
		return "email:" + user.Emailaddress
	default:
		return "name:" + user.Displayname
	}
}

// submissionLimiter allows one submission per interval for each key.
type submissionLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	last     map[string]time.Time
}

func newSubmissionLimiter(interval time.Duration) *submissionLimiter {
	return &submissionLimiter{interval: interval, last: make(map[string]time.Time)}
}

func (l *submissionLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && now.Sub(t) < l.interval {
		return false
	}
	for k, t := range l.last {
		if now.Sub(t) >= l.interval {
			delete(l.last, k)
		}
	}
	l.last[key] = now
	return true
}

// release frees a slot reserved by allow at the given time, e.g. when the
// submission could not be stored.
func (l *submissionLimiter) release(key string, reserved time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if t, ok := l.last[key]; ok && t.Equal(reserved) {
		delete(l.last, key)
	}
}

func getTimeStr(currentTime time.Time) string {
	year, month, day := currentTime.Date()
	hour, min, sec := currentTime.Clock()

	yyyy := strconv.Itoa(year)
	mm := fmt.Sprintf("%02d", int(month))
	dd := fmt.Sprintf("%02d", day)
	hr := fmt.Sprintf("%02d", hour)
	mn := fmt.Sprintf("%02d", min)
	ss := fmt.Sprintf("%02d", sec)
	return yyyy + mm + dd + hr + mn + ss
}
