// Package publicurl builds the URLs the hub hands back for what it stores:
// the `hub_url` of a pushed artifact and the `receipt_url` of an uploaded
// receipt.
//
// Through 0.31.9 these were literal https://treeship.dev/... strings, so a
// self-hosted hub told every client to look for its data on treeship.dev,
// where it never was (0.31.9 full test, CLI-12). The rule now, in order:
//
//  1. TREESHIP_PUBLIC_URL, when set: the base of the site that renders
//     pages for this hub's data. A self-hoster with a site sets it.
//  2. Otherwise, when the request reached a treeship.dev host (checked on
//     X-Forwarded-Host first, because the public hub sits behind a proxy,
//     then Host): today's pages on https://treeship.dev. Production needs
//     no configuration and keeps its behaviour.
//  3. Otherwise this hub has no page site, so the honest URL is the hub's
//     own API URL for the object, built from the request's origin. That
//     URL works: `treeship verify <origin>/v1/receipt/<id>` fetches it.
package publicurl

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// EnvPublicURL names the site that renders pages for this hub's data.
const EnvPublicURL = "TREESHIP_PUBLIC_URL"

const treeshipPages = "https://treeship.dev"

// Artifact is the URL returned as `hub_url` for a pushed artifact.
func Artifact(r *http.Request, artifactID string) string {
	if base := PageBase(r); base != "" {
		return base + "/verify/" + artifactID
	}
	return Origin(r) + "/v1/artifacts/" + artifactID
}

// Receipt is the URL returned as `receipt_url` for an uploaded receipt.
func Receipt(r *http.Request, sessionID string) string {
	if base := PageBase(r); base != "" {
		return base + "/receipt/" + sessionID
	}
	return Origin(r) + "/v1/receipt/" + sessionID
}

// PageBase is the base URL of the site that renders pages for this hub's
// data, or "" when there is none.
func PageBase(r *http.Request) string {
	if v := strings.TrimSpace(os.Getenv(EnvPublicURL)); v != "" {
		return strings.TrimRight(v, "/")
	}
	if isTreeshipHost(effectiveHost(r)) {
		return treeshipPages
	}
	return ""
}

// Origin is scheme://host as the client addressed this hub, honouring the
// proxy headers Railway and similar front doors set.
func Origin(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := firstForwarded(r.Header.Get("X-Forwarded-Proto")); p != "" {
		scheme = p
	}
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	return scheme + "://" + host
}

// effectiveHost is the host the client addressed, without a port.
func effectiveHost(r *http.Request) string {
	host := firstForwarded(r.Header.Get("X-Forwarded-Host"))
	if host == "" {
		host = r.Host
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(h)
	}
	return strings.ToLower(host)
}

func isTreeshipHost(host string) bool {
	return host == "treeship.dev" || strings.HasSuffix(host, ".treeship.dev")
}

// A forwarding header may carry a comma-separated chain; the first entry
// is the one the client used.
func firstForwarded(v string) string {
	if i := strings.IndexByte(v, ','); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}
