/*
 * Copyright FMR LLC <opensource@fidelity.com>
 *
 * SPDX-License-Identifier: Apache
 */
package router

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/fidelity/theliv/pkg/config"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

func ConfigInfo(r chi.Router) {
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		config := getUIConfig()
		if empty := processEmpty(w, r, config); !empty {
			render.Respond(w, r, config)
		}
	})
}

func getUIConfig() *ConfigData {
	thelivcfg := config.GetThelivConfig()
	return &ConfigData{
		EmailAddr:       thelivcfg.EmailAddr,
		DevelopedByTeam: thelivcfg.DevelopedByTeam,
		VideoLink:       safeExternalURL(thelivcfg.VideoLink),
	}
}

// safeExternalURL returns link only when it is an absolute https URL with a host,
// so the UI never receives javascript:, data: or other script-capable schemes.
func safeExternalURL(link string) string {
	link = strings.TrimSpace(link)
	if link == "" {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil || !strings.EqualFold(u.Scheme, "https") || u.Host == "" {
		return ""
	}
	return u.String()
}

type ConfigData struct {
	EmailAddr       string `json:"emailAddr,omitempty"`
	DevelopedByTeam string `json:"developedByTeam,omitempty"`
	VideoLink       string `json:"videoLink,omitempty"`
}
