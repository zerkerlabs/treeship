// Package version answers "which build is this?" for the hub.
//
// The public hub had no version endpoint at all (/health, /version and
// /v1/version were 404s, 0.31.9 full test, WEB-4), so nobody could tell
// from outside whether a fix had been deployed. The values come from
// -ldflags at build time (see the Dockerfile); when they are not set, the
// module's own build info fills in what it can, and the rest reads "dev".
package version

import (
	"encoding/json"
	"net/http"
	"runtime"
	"runtime/debug"
)

// Set with -ldflags "-X .../internal/version.Version=... " at build time.
var (
	Version = ""
	Commit  = ""
	BuiltAt = ""
)

// Info is the document /v1/version returns.
type Info struct {
	Service string `json:"service"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
	Go      string `json:"go"`
	Dirty   bool   `json:"dirty,omitempty"`
}

// Current is the build info, from ldflags first and Go's own build
// metadata second.
func Current() Info {
	info := Info{
		Service: "treeship-hub",
		Version: Version,
		Commit:  Commit,
		BuiltAt: BuiltAt,
		Go:      runtime.Version(),
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.BuiltAt == "" {
					info.BuiltAt = s.Value
				}
			case "vcs.modified":
				info.Dirty = s.Value == "true"
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	if info.Commit == "" {
		info.Commit = "unknown"
	}
	if info.BuiltAt == "" {
		info.BuiltAt = "unknown"
	}
	return info
}

// Handler serves GET /v1/version (and its aliases). Never cached: the
// point of the endpoint is to learn what is running right now.
func Handler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(Current())
}
