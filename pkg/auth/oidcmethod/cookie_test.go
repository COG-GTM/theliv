/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package oidcmethod

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestJoinCookiesRoundTrip(t *testing.T) {
	for _, size := range []int{10, maxValueLength, maxValueLength + 1, maxValueLength * maxChunks} {
		value := strings.Repeat("a", size)
		got, err := joinCookies(context.Background(), IDTokenKey, splitCookie(IDTokenKey, value))
		if err != nil {
			t.Fatalf("size %d: unexpected error: %v", size, err)
		}
		if got != value {
			t.Fatalf("size %d: round trip mismatch", size)
		}
	}
}

func TestJoinCookiesRejectsHugeChunkCount(t *testing.T) {
	for _, v := range []string{"999999999:x", "9223372036854775807:x", "9:x"} {
		done := make(chan error, 1)
		go func(v string) {
			_, err := joinCookies(context.Background(), IDTokenKey,
				[]*http.Cookie{{Name: IDTokenKey, Value: v}})
			done <- err
		}(v)
		select {
		case err := <-done:
			if err == nil {
				t.Fatalf("%q: expected error", v)
			}
		case <-time.After(time.Second):
			t.Fatalf("%q: joinCookies did not return promptly", v)
		}
	}
}

func TestJoinCookiesRejectsNonPositiveChunkCount(t *testing.T) {
	for _, v := range []string{"0:x", "-5:x"} {
		if _, err := joinCookies(context.Background(), IDTokenKey,
			[]*http.Cookie{{Name: IDTokenKey, Value: v}}); err == nil {
			t.Fatalf("%q: expected error", v)
		}
	}
}

func TestJoinCookiesRejectsMissingChunk(t *testing.T) {
	cookies := []*http.Cookie{
		{Name: IDTokenKey, Value: "3:a"},
		{Name: IDTokenKey + "-1", Value: "b"},
	}
	if _, err := joinCookies(context.Background(), IDTokenKey, cookies); err == nil {
		t.Fatal("expected error for missing chunk")
	}
}
