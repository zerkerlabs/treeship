package artifacts

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zerkerlabs/treeship/packages/hub/internal/auth"
	"github.com/zerkerlabs/treeship/packages/hub/internal/contentaddress"
	"github.com/zerkerlabs/treeship/packages/hub/internal/db"
	"github.com/zerkerlabs/treeship/packages/hub/internal/dpop"
	"github.com/zerkerlabs/treeship/packages/hub/internal/publicurl"
	"github.com/zerkerlabs/treeship/packages/hub/internal/rekor"
)

type Handlers struct {
	DB *sql.DB
	// Rekor is the transparency log client. Nil disables anchoring (tests,
	// air-gapped deployments); every push then reports rekor as skipped.
	Rekor *rekor.Client
}

// rekorView is the anchoring outcome as returned to clients. `rekor_index`
// stays at the top level for older CLIs; newer ones read this object.
func rekorView(status, reason, entry *string, index *int64) map[string]any {
	if status == nil {
		return nil
	}
	v := map[string]any{"status": *status}
	if reason != nil && *reason != "" {
		v["reason"] = *reason
	}
	if index != nil {
		v["log_index"] = *index
	}
	if entry != nil && *entry != "" {
		v["entry"] = json.RawMessage(*entry)
	}
	return v
}

// anchor runs one anchoring attempt and records the outcome, whatever it is.
func (h *Handlers) anchor(r *http.Request, artifactID, envelopeJSON, dockID string) rekor.Result {
	var res rekor.Result
	if h.Rekor == nil {
		res = rekor.Result{Status: rekor.StatusSkipped, Reason: "this hub has Rekor anchoring disabled"}
	} else {
		var shipPubKey []byte
		row := h.DB.QueryRow(`SELECT ship_public_key FROM ships WHERE dock_id = ?`, dockID)
		if err := row.Scan(&shipPubKey); err != nil || len(shipPubKey) == 0 {
			res = rekor.Result{Status: rekor.StatusSkipped, Reason: "dock has no registered ship key"}
		} else {
			res = h.Rekor.Anchor(r.Context(), envelopeJSON, shipPubKey)
		}
	}
	if err := db.SetRekorResult(h.DB, artifactID, res.Status, res.Reason, res.LogIndex, res.Entry); err != nil {
		log.Printf("rekor: failed to store outcome for %s: %v", artifactID, err)
	}
	return res
}

type pushRequest struct {
	ArtifactID   string          `json:"artifact_id"`
	PayloadType  string          `json:"payload_type"`
	EnvelopeJSON string          `json:"envelope_json"`
	Digest       string          `json:"digest"`
	SignedAt     json.RawMessage `json:"signed_at"`
	ParentID     *string         `json:"parent_id"`
}

// parseSignedAt handles both unix int and RFC 3339 string.
// parseSignedAt reads the caller-supplied signed_at, accepting a unix integer
// or an RFC3339 string. Returns ok=false when the value is absent or
// unparseable.
//
// It used to return time.Now() on every failure path -- and the string branch
// never parsed at all, so a perfectly good RFC3339 timestamp was silently
// replaced by server time. That turned "the client sent something we could not
// read" into "the client sent this plausible moment," which is the worst of
// both: the bad input is not rejected, and the fabricated value is
// indistinguishable from a real one to everything downstream.
//
// This value is caller-supplied and the Hub does not verify envelopes, so it
// is untrusted either way. But untrusted-and-recorded-as-given is auditable;
// untrusted-and-quietly-replaced is not.
func parseSignedAt(raw json.RawMessage) (int64, bool) {
	if len(raw) == 0 || string(raw) == "null" {
		return 0, false
	}
	var ts int64
	if json.Unmarshal(raw, &ts) == nil {
		return ts, true
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.Unix(), true
			}
		}
	}
	return 0, false
}

// Push handles POST /v1/artifacts [DPoP authenticated]
func (h *Handlers) Push(w http.ResponseWriter, r *http.Request) {
	// DPoP verification.
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return // dpop.Verify already wrote the 401 response
	}

	var req pushRequest
	// Cap request body at 10 MB (same rule as receipts): an authenticated
	// dock must not be able to buffer arbitrary gigabytes into hub memory.
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.ArtifactID == "" || req.PayloadType == "" || req.EnvelopeJSON == "" || req.Digest == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing required fields"})
		return
	}

	signedAt, ok := parseSignedAt(req.SignedAt)
	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "signed_at must be a unix timestamp or an RFC3339 string",
		})
		return
	}

	// Re-derive identity from the envelope's own bytes before believing any
	// of it. Until this existed, `artifact_id`, `digest` and `payload_type`
	// were stored exactly as submitted and never checked against the
	// envelope -- so an authenticated dock could upload unrelated bytes
	// under a legitimate id, win the first-write race, and have the real
	// upload silently dropped by ON CONFLICT DO NOTHING while both callers
	// got a 200.
	derived, err := contentaddress.Check(
		req.EnvelopeJSON, req.ArtifactID, req.Digest, req.PayloadType)
	if err != nil {
		status := http.StatusBadRequest
		// Log a mismatch: a malformed envelope is a broken client, but
		// submitted fields that disagree with the bytes is someone probing
		// the namespace, and that is worth being able to see.
		if errors.Is(err, contentaddress.ErrMismatch) {
			log.Printf("SECURITY: dock %s submitted artifact fields that do not match the envelope: %v",
				dockID, err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	hubURL := publicurl.Artifact(derived.ArtifactID)

	// Indexed fields come from the envelope, not the request. See
	// contentaddress.DeriveIndexable: an index built from caller-supplied
	// metadata lets an uploader choose how their artifact is found.
	idx := contentaddress.DeriveIndexable(req.EnvelopeJSON)

	artifact := &db.Artifact{
		Kind:         idx.Kind,
		Actor:        idx.Actor,
		ArtifactID:   req.ArtifactID,
		PayloadType:  req.PayloadType,
		EnvelopeJSON: req.EnvelopeJSON,
		Digest:       req.Digest,
		SignedAt:     signedAt,
		ParentID:     req.ParentID,
		HubURL:       hubURL,
		DockID:       &dockID,
	}

	inserted, err := db.InsertArtifact(h.DB, artifact)
	if err != nil {
		log.Printf("insert artifact error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to store artifact"})
		return
	}

	if !inserted {
		// Something is already stored under this id. Now that the id is
		// derived from the bytes, identical bytes are the only ordinary
		// case -- a genuine re-push, which succeeds idempotently.
		existing, gerr := db.GetArtifact(h.DB, derived.ArtifactID)
		if gerr != nil || existing == nil {
			log.Printf("artifact %s reported as existing but could not be read: %v",
				derived.ArtifactID, gerr)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to store artifact"})
			return
		}
		if !contentaddress.SameBytes(existing.EnvelopeJSON, req.EnvelopeJSON) {
			// Two different envelopes deriving one id means a 128-bit
			// SHA-256 collision or a bug in the derivation. Either way the
			// stored bytes stay, the caller is told plainly, and -- the part
			// that matters -- we do not fall through to Rekor and stamp a
			// transparency-log index onto another dock's artifact.
			log.Printf("SECURITY: dock %s pushed artifact %s whose bytes differ from the stored copy",
				dockID, derived.ArtifactID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":       "artifact id already stored with different bytes",
				"artifact_id": derived.ArtifactID,
			})
			return
		}
		// Same bytes: idempotent success. An artifact that already holds a
		// Rekor entry keeps it -- a second anchor would replace a proof for no
		// gain. One that never got anchored (every push before TS-2026-003
		// was fixed, or a transient Rekor failure) is retried, so re-pushing
		// is how an operator backfills.
		resp := map[string]any{
			"artifact_id": existing.ArtifactID,
			"hub_url":     existing.HubURL,
			"duplicate":   true,
		}
		if existing.RekorEntry != nil && *existing.RekorEntry != "" {
			resp["rekor_index"] = existing.RekorIndex
			resp["rekor"] = rekorView(existing.RekorStatus, existing.RekorReason, existing.RekorEntry, existing.RekorIndex)
		} else {
			res := h.anchor(r, existing.ArtifactID, existing.EnvelopeJSON, dockID)
			resp["rekor_index"] = res.LogIndex
			resp["rekor"] = res
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// Rekor anchoring. Best-effort in that a Rekor outage never fails the
	// push -- but never silent: the outcome is stored and returned, so a
	// failed anchor is visible as failed rather than as a missing field.
	res := h.anchor(r, req.ArtifactID, req.EnvelopeJSON, dockID)

	resp := map[string]interface{}{
		"artifact_id": req.ArtifactID,
		"hub_url":     hubURL,
		"rekor":       res,
	}
	if res.LogIndex != nil {
		resp["rekor_index"] = *res.LogIndex
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// Workspace handles GET /v1/workspace/{dockId}.
//
// Auth is delegated to auth.ResolveReader, which accepts either DPoP (for
// CLI callers) or ?session=TOKEN (for browser callers loading a share link).
// Whichever mechanism succeeds, the resolved dock_id must match the
// {dockId} in the path; you can never read another ship's workspace.
func (h *Handlers) Workspace(w http.ResponseWriter, r *http.Request) {
	authedDockID := auth.ResolveReader(h.DB, w, r)
	if authedDockID == "" {
		return // ResolveReader already wrote the error response
	}

	dockID := chi.URLParam(r, "dockId")
	if dockID == "" {
		dockID = authedDockID
	}
	if dockID != authedDockID {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "you can only access your own workspace"})
		return
	}

	ship, err := db.GetShip(h.DB, dockID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "ship not found"})
		return
	}

	artifacts, err := db.ListArtifactsByDock(h.DB, dockID)
	if err != nil {
		log.Printf("list artifacts error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to list artifacts"})
		return
	}

	type artifactSummary struct {
		ArtifactID  string  `json:"artifact_id"`
		PayloadType string  `json:"payload_type"`
		Digest      string  `json:"digest"`
		SignedAt    int64   `json:"signed_at"`
		ParentID    *string `json:"parent_id"`
		HubURL      string  `json:"hub_url"`
		RekorIndex  *int64  `json:"rekor_index"`
	}

	summaries := make([]artifactSummary, len(artifacts))
	for i, a := range artifacts {
		summaries[i] = artifactSummary{
			ArtifactID:  a.ArtifactID,
			PayloadType: a.PayloadType,
			Digest:      a.Digest,
			SignedAt:    a.SignedAt,
			ParentID:    a.ParentID,
			HubURL:      a.HubURL,
			RekorIndex:  a.RekorIndex,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"dock_id":        dockID,
		"created_at":     ship.CreatedAt,
		"artifact_count": len(summaries),
		"artifacts":      summaries,
	})
}

// Pull handles GET /v1/artifacts/:id
func (h *Handlers) Pull(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing artifact id"})
		return
	}

	artifact, err := db.GetArtifact(h.DB, id)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "artifact not found"})
		return
	}

	// Include the ship's public key so browsers can do full Ed25519 verification
	resp := map[string]interface{}{
		"artifact_id":   artifact.ArtifactID,
		"payload_type":  artifact.PayloadType,
		"envelope_json": artifact.EnvelopeJSON,
		"digest":        artifact.Digest,
		"signed_at":     artifact.SignedAt,
		"parent_id":     artifact.ParentID,
		"hub_url":       artifact.HubURL,
		"rekor_index":   artifact.RekorIndex,
		"dock_id":       artifact.DockID,
	}
	if v := rekorView(artifact.RekorStatus, artifact.RekorReason, artifact.RekorEntry, artifact.RekorIndex); v != nil {
		resp["rekor"] = v
	}

	if artifact.DockID != nil {
		shipPubKey, err := db.GetShipPublicKey(h.DB, *artifact.DockID)
		if err == nil && shipPubKey != "" {
			resp["ship_public_key"] = shipPubKey
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
