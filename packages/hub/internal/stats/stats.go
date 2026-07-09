// Package stats implements the public adoption metrics endpoint:
//
//	GET /v1/stats  (public, no auth)
//
// One JSON document with the counts the hub's own database can answer:
// artifacts pushed, docks attached and active, session receipts uploaded,
// distinct agents seen. Verify-page traffic and package downloads live in
// external systems (site analytics, npm/crates registries) and are
// deliberately NOT proxied here: the hub reports only what it can count
// from its own tables, so every number on this endpoint is checkable
// against the same database the transparency endpoints serve.
//
// The endpoint returns counts only, never identifiers, so it exposes
// nothing about who pushed what. "last_7d" windows use artifacts.signed_at
// (there is no inserted_at column); artifacts are signed and pushed in the
// same breath on every normal path, so signing time is the honest proxy
// for push time, and a backfill of old artifacts shows up as total growth
// without inflating the activity window.
package stats

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"
)

type Handlers struct {
	DB *sql.DB
}

type artifactStats struct {
	Total  int64 `json:"total"`
	Last7d int64 `json:"last_7d"`
}

type dockStats struct {
	Total          int64 `json:"total"`
	AttachedLast7d int64 `json:"attached_last_7d"`
	// ActiveLast7d counts distinct docks that pushed at least one artifact
	// in the window -- the adoption number that matters more than signups.
	ActiveLast7d int64 `json:"active_last_7d"`
}

type sessionStats struct {
	Total            int64 `json:"total"`
	ReceiptsUploaded int64 `json:"receipts_uploaded"`
	UploadedLast7d   int64 `json:"uploaded_last_7d"`
}

type agentStats struct {
	Total      int64 `json:"total"`
	SeenLast7d int64 `json:"seen_last_7d"`
}

type response struct {
	Artifacts   artifactStats `json:"artifacts"`
	Docks       dockStats     `json:"docks"`
	Sessions    sessionStats  `json:"sessions"`
	Agents      agentStats    `json:"agents"`
	GeneratedAt string        `json:"generated_at"`
}

// Stats handles GET /v1/stats.
//
// Any query failure returns 500 rather than a partial document: a stats
// endpoint that silently reports zeros on error reads as "no adoption",
// which is a lie in the dangerous direction.
func (h *Handlers) Stats(w http.ResponseWriter, r *http.Request) {
	cutoff := time.Now().Add(-7 * 24 * time.Hour).Unix()

	var resp response
	queries := []struct {
		dst   *int64
		query string
		args  []any
	}{
		{&resp.Artifacts.Total, `SELECT COUNT(*) FROM artifacts`, nil},
		{&resp.Artifacts.Last7d, `SELECT COUNT(*) FROM artifacts WHERE signed_at >= ?`, []any{cutoff}},
		{&resp.Docks.Total, `SELECT COUNT(*) FROM ships`, nil},
		{&resp.Docks.AttachedLast7d, `SELECT COUNT(*) FROM ships WHERE created_at >= ?`, []any{cutoff}},
		{&resp.Docks.ActiveLast7d, `SELECT COUNT(DISTINCT dock_id) FROM artifacts WHERE dock_id IS NOT NULL AND signed_at >= ?`, []any{cutoff}},
		{&resp.Sessions.Total, `SELECT COUNT(*) FROM sessions`, nil},
		{&resp.Sessions.ReceiptsUploaded, `SELECT COUNT(*) FROM sessions WHERE receipt_json IS NOT NULL`, nil},
		{&resp.Sessions.UploadedLast7d, `SELECT COUNT(*) FROM sessions WHERE uploaded_at IS NOT NULL AND uploaded_at >= ?`, []any{cutoff}},
		{&resp.Agents.Total, `SELECT COUNT(DISTINCT agent_id) FROM ship_agents`, nil},
		{&resp.Agents.SeenLast7d, `SELECT COUNT(DISTINCT agent_id) FROM ship_agents WHERE last_seen >= ?`, []any{cutoff}},
	}
	for _, item := range queries {
		if err := h.DB.QueryRow(item.query, item.args...).Scan(item.dst); err != nil {
			log.Printf("stats: %s: %v", item.query, err)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"stats unavailable"}`, http.StatusInternalServerError)
			return
		}
	}
	resp.GeneratedAt = time.Now().UTC().Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("stats: encode: %v", err)
	}
}
