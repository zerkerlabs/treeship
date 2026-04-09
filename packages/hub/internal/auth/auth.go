// Package auth resolves the caller's dock_id for read endpoints that accept
// both DPoP proofs (CLI callers) and short-lived workspace share tokens
// (browser callers from a `treeship hub open` link).
//
// Endpoints that mutate state (push artifacts, mint sessions, publish merkle
// checkpoints, upload receipts) must keep using dpop.Verify directly. This
// helper is for read-only handlers.
package auth

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"time"

	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dpop"
)

// ResolveReader returns the dock_id the caller is authorized to read for.
//
// Two paths:
//
//  1. ?session=TOKEN query param. Looked up against workspace_sessions; if
//     valid (and unexpired), the bound dock_id is returned. If the token is
//     present but invalid/expired, this writes a 401 and returns "" — we
//     fail closed rather than silently falling through to DPoP, otherwise a
//     stale share link would surface a confusing "missing Authorization
//     header" error to a browser user.
//
//  2. DPoP proof. Same semantics as dpop.Verify — on success returns the
//     authenticated dock_id, on failure writes the appropriate 401.
//
// On any failure path the response has already been written; callers should
// just `return` when "" is received.
func ResolveReader(database *sql.DB, w http.ResponseWriter, r *http.Request) string {
	if sessionToken := r.URL.Query().Get("session"); sessionToken != "" {
		now := time.Now().Unix()
		boundDockID, err := db.GetWorkspaceSessionDockID(database, sessionToken, now)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid or expired session token"})
			return ""
		}
		return boundDockID
	}

	return dpop.Verify(database, w, r)
}
