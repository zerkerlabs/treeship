// Package receipts implements the public Session Receipt v1 share endpoints:
//
//	PUT /v1/receipt/:session_id  (DPoP authenticated)
//	GET /v1/receipt/:session_id  (public, no auth)
//
// PUT stores a deterministic Session Receipt JSON associated with the calling
// dock. The endpoint is idempotent: a second PUT for the same session_id
// overwrites the first.
//
// GET is fully public and the URL is permanent. It enables A2A consumption,
// shareable links, and offline verification.
package receipts

import (
	"database/sql"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/zerkerlabs/treeship/packages/hub/internal/db"
	"github.com/zerkerlabs/treeship/packages/hub/internal/dpop"
	"github.com/zerkerlabs/treeship/packages/hub/internal/publicurl"
)

type Handlers struct {
	DB *sql.DB
}

// receipt is a partial mirror of the Rust treeship_core::session::SessionReceipt
// struct -- only the fields the Hub needs to extract for indexing. The full
// receipt body is round-tripped as JSON without re-serialization.
type receipt struct {
	Type         string         `json:"type"`
	Session      sessionSection `json:"session"`
	Participants struct {
		TotalAgents      int `json:"total_agents"`
		SpawnedSubagents int `json:"spawned_subagents"`
		Handoffs         int `json:"handoffs"`
		MaxDepth         int `json:"max_depth"`
		Hosts            int `json:"hosts"`
		ToolRuntimes     int `json:"tool_runtimes"`
	} `json:"participants"`
	AgentGraph struct {
		Nodes []agentNode `json:"nodes"`
	} `json:"agent_graph"`
	Timeline []json.RawMessage `json:"timeline"`
}

type sessionSection struct {
	ID         string  `json:"id"`
	Name       *string `json:"name,omitempty"`
	Mode       string  `json:"mode"`
	StartedAt  string  `json:"started_at"`
	EndedAt    *string `json:"ended_at,omitempty"`
	Status     string  `json:"status"`
	DurationMS *int64  `json:"duration_ms,omitempty"`
}

type agentNode struct {
	AgentID         string  `json:"agent_id"`
	AgentInstanceID string  `json:"agent_instance_id"`
	AgentName       string  `json:"agent_name"`
	AgentRole       *string `json:"agent_role,omitempty"`
	HostID          string  `json:"host_id"`
	StartedAt       *string `json:"started_at,omitempty"`
	CompletedAt     *string `json:"completed_at,omitempty"`
	Status          *string `json:"status,omitempty"`
}

// PutReceipt handles PUT /v1/receipt/:session_id [DPoP authenticated].
//
// The session_id path parameter MUST match the session.id field inside the
// receipt body, otherwise the request is rejected with 400. This prevents a
// dock from accidentally (or maliciously) overwriting another session's slot
// by mismatched routing.
//
// Successful PUTs upsert into the sessions table and refresh the per-ship
// agent registry from agent_graph.nodes. The response includes the public
// receipt URL.
func (h *Handlers) PutReceipt(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return // dpop.Verify already wrote the 401 response
	}

	pathSessionID := chi.URLParam(r, "session_id")
	if pathSessionID == "" {
		writeError(w, http.StatusBadRequest, "missing session_id in path")
		return
	}
	if len(pathSessionID) > 128 {
		writeError(w, http.StatusBadRequest, "session_id too long (max 128 chars)")
		return
	}

	// Cap request body at 10 MB to prevent memory-DoS from authenticated docks.
	const maxReceiptBytes = 10 << 20
	r.Body = http.MaxBytesReader(w, r.Body, maxReceiptBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "receipt body exceeds 10 MB limit")
		return
	}
	if len(body) == 0 {
		writeError(w, http.StatusBadRequest, "empty request body")
		return
	}

	var rcpt receipt
	if err := json.Unmarshal(body, &rcpt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid receipt JSON: "+err.Error())
		return
	}

	if rcpt.Type != "treeship/session-receipt/v1" {
		writeError(w, http.StatusBadRequest, "unsupported receipt type: "+rcpt.Type)
		return
	}
	if rcpt.Session.ID == "" {
		writeError(w, http.StatusBadRequest, "receipt missing session.id")
		return
	}
	if rcpt.Session.ID != pathSessionID {
		writeError(w, http.StatusBadRequest, "session_id in path does not match receipt body")
		return
	}

	receiptJSON := string(body)
	now := time.Now().Unix()
	status := "closed"
	if rcpt.Session.Status != "" {
		status = rcpt.Session.Status
	}

	sess := &db.Session{
		SessionID:   pathSessionID,
		DockID:      dockID,
		Name:        rcpt.Session.Name,
		StartedAt:   strPtrIfNonEmpty(rcpt.Session.StartedAt),
		EndedAt:     rcpt.Session.EndedAt,
		DurationMS:  rcpt.Session.DurationMS,
		Status:      status,
		AgentCount:  rcpt.Participants.TotalAgents,
		ActionCount: len(rcpt.Timeline),
		ReceiptJSON: &receiptJSON,
		UploadedAt:  &now,
	}

	// Atomic write-once insert. Ownership is established on first write
	// and never transferred. Receipt content is immutable once sealed.
	outcome, err := db.InsertSessionWriteOnce(h.DB, sess)
	if err != nil {
		log.Printf("insert session error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to store receipt")
		return
	}
	switch outcome {
	case "owned_by_other":
		writeError(w, http.StatusForbidden, "session_id is owned by another dock")
		return
	case "tombstoned":
		writeError(w, http.StatusGone, "this receipt was taken down by its publisher; the session id is retired")
		return
	case "already_sealed":
		writeError(w, http.StatusConflict, "receipt already uploaded for this session; receipts are write-once")
		return
	}

	// Refresh the per-ship agent registry from agent_graph.nodes.
	// Failures here are logged but do not fail the PUT -- the receipt is the
	// authoritative artifact, the agents table is a derived index.
	for _, node := range rcpt.AgentGraph.Nodes {
		agent := &db.ShipAgent{
			DockID:   dockID,
			AgentID:  node.AgentInstanceID,
			Label:    strPtrIfNonEmpty(node.AgentName),
			Role:     node.AgentRole,
			Model:    nil, // not present in receipt schema
			Host:     strPtrIfNonEmpty(node.HostID),
			Status:   node.Status,
			LastSeen: now,
		}
		if err := db.UpsertShipAgent(h.DB, agent); err != nil {
			log.Printf("upsert ship_agent (%s) error: %v", node.AgentInstanceID, err)
		}
	}

	receiptURL := publicurl.Receipt(pathSessionID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id":  pathSessionID,
		"receipt_url": receiptURL,
		"agents":      len(rcpt.AgentGraph.Nodes),
		"events":      len(rcpt.Timeline),
		"uploaded_at": now,
	})
}

// GetReceipt handles GET /v1/receipt/:session_id [public, no auth].
//
// Three response shapes:
//
//	200 + receipt body  -- session exists, receipt is uploaded
//	403 "session still open"  -- session row exists, receipt_json is null
//	404 "session not found"   -- no row at all
func (h *Handlers) GetReceipt(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing session_id in path")
		return
	}
	if len(sessionID) > 128 {
		writeError(w, http.StatusBadRequest, "session_id too long")
		return
	}

	sess, err := db.GetSession(h.DB, sessionID)
	if err != nil {
		// sql.ErrNoRows -- treat as not found.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "session not found"})
		return
	}

	// Taken down by its dock: 410 Gone, a short reason, never the old bytes
	// (the body was removed when the tombstone was written), and no caching
	// so a cached 200 is not refreshed from here.
	if sess.TombstonedAt != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusGone)
		resp := map[string]interface{}{
			"error":         "receipt removed by its publisher",
			"session_id":    sess.SessionID,
			"tombstoned_at": *sess.TombstonedAt,
		}
		if sess.TombstoneReason != nil && *sess.TombstoneReason != "" {
			resp["reason"] = *sess.TombstoneReason
		}
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	if sess.ReceiptJSON == nil || *sess.ReceiptJSON == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "session still open"})
		return
	}

	// Cache aggressively -- once a receipt exists for a session_id it never
	// changes (idempotency on the PUT side guarantees this for a given dock).
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
	_, _ = w.Write([]byte(*sess.ReceiptJSON))
}

// DeleteReceipt handles DELETE /v1/receipt/:session_id [DPoP authenticated].
//
// Only the dock that published the receipt can take it down; the same
// DPoP proof rules as PutReceipt apply (method and URL bound, jti burned,
// so a captured proof cannot be replayed). The receipt body is removed and
// the row keeps only the id, the dock and the tombstone time (plus an
// optional short reason from the body: {"reason": "..."}, capped at 200
// bytes on a character boundary); the name, timing and counts are cleared
// with the body. GetReceipt answers 410 Gone from then on; PutReceipt on the id
// answers 410 too, so the slot is never refilled.
func (h *Handlers) DeleteReceipt(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return
	}
	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" || len(sessionID) > 128 {
		writeError(w, http.StatusBadRequest, "missing or too long session_id in path")
		return
	}
	reason := ""
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if body, err := io.ReadAll(r.Body); err == nil && len(body) > 0 {
		var req struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(body, &req) == nil {
			reason = truncateReason(req.Reason, 200)
		}
	}
	now := time.Now().Unix()
	outcome, err := db.TombstoneSession(h.DB, sessionID, dockID, reason, now)
	if err != nil {
		log.Printf("tombstone session error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to take the receipt down")
		return
	}
	switch outcome {
	case "not_found":
		writeError(w, http.StatusNotFound, "session not found")
		return
	case "owned_by_other":
		writeError(w, http.StatusForbidden, "session_id is owned by another dock")
		return
	case "already":
		writeError(w, http.StatusGone, "receipt already taken down")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"session_id":    sessionID,
		"status":        "tombstoned",
		"tombstoned_at": now,
	})
}

// --- helpers ---

// truncateReason caps a reason at max bytes without splitting a UTF-8
// sequence, so a long multibyte reason never comes back with a broken
// final character.
func truncateReason(reason string, max int) string {
	if len(reason) <= max {
		return reason
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(reason[cut]) {
		cut--
	}
	return reason[:cut]
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func strPtrIfNonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
