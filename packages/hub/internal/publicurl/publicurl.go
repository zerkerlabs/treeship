// Package publicurl builds the URLs the hub hands back for what it stores:
// the `hub_url` of a pushed artifact and the `receipt_url` of an uploaded
// receipt.
//
// Through 0.31.9 these were literal https://treeship.dev/... strings, so a
// self-hosted hub told every client to look for its data on treeship.dev,
// where it never was (0.31.9 full test, CLI-12). The rule now, in order:
//
//  1. TREESHIP_PUBLIC_URL, when set: the base of the site that renders
//     pages for this hub's data (https://treeship.dev for the public hub).
//  2. TREESHIP_HUB_PUBLIC_URL, when set: this hub's own public origin. A
//     self-hosted hub with no page site returns its own API URLs
//     (<origin>/v1/receipt/<id>, <origin>/v1/artifacts/<id>), which
//     `treeship verify <url>` accepts.
//  3. Otherwise today's pages on https://treeship.dev. Production needs no
//     configuration and keeps its behaviour.
//
// Nothing here reads Host or X-Forwarded-Host. These URLs are stored with
// the artifact and served to every later reader, so a request header must
// not be able to choose them.
package publicurl

import (
	"os"
	"strings"
)

// EnvPublicURL names the site that renders pages for this hub's data.
const EnvPublicURL = "TREESHIP_PUBLIC_URL"

// EnvHubPublicURL names this hub's own public origin, for a hub with no
// page site.
const EnvHubPublicURL = "TREESHIP_HUB_PUBLIC_URL"

const treeshipPages = "https://treeship.dev"

// Artifact is the URL returned as `hub_url` for a pushed artifact.
func Artifact(artifactID string) string {
	if base := pageBase(); base != "" {
		return base + "/verify/" + artifactID
	}
	return hubOrigin() + "/v1/artifacts/" + artifactID
}

// Receipt is the URL returned as `receipt_url` for an uploaded receipt.
func Receipt(sessionID string) string {
	if base := pageBase(); base != "" {
		return base + "/receipt/" + sessionID
	}
	return hubOrigin() + "/v1/receipt/" + sessionID
}

// pageBase is the base of the site that renders pages for this hub's data,
// or "" when the hub is configured to answer with its own API URLs.
func pageBase() string {
	if v := env(EnvPublicURL); v != "" {
		return v
	}
	if env(EnvHubPublicURL) != "" {
		return ""
	}
	return treeshipPages
}

func hubOrigin() string {
	return env(EnvHubPublicURL)
}

func env(name string) string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv(name)), "/")
}
