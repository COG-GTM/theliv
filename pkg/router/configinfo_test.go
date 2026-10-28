/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import "testing"

func TestSafeExternalURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"empty", "", ""},
		{"https", "https://www.youtube.com/watch?v=abc", "https://www.youtube.com/watch?v=abc"},
		{"https uppercase scheme", "HTTPS://example.com/video", "https://example.com/video"},
		{"surrounding whitespace", "  https://example.com/v  ", "https://example.com/v"},
		{"javascript", "javascript:alert(1)", ""},
		{"javascript mixed case", "JaVaScRiPt:alert(document.domain)", ""},
		{"javascript leading space", " javascript:alert(1)", ""},
		{"data", "data:text/html,<script>alert(1)</script>", ""},
		{"vbscript", "vbscript:msgbox(1)", ""},
		{"http", "http://example.com/video", ""},
		{"relative", "/videos/howto.mp4", ""},
		{"protocol relative", "//evil.example.com/x", ""},
		{"https without host", "https:///path", ""},
		{"unparseable", "https://exa mple.com/%zz", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeExternalURL(tt.input); got != tt.want {
				t.Errorf("safeExternalURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
