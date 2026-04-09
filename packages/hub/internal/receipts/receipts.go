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

	"github.com/go-chi/chi/v5"
	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dpop"
)

type Handlers struct {
	DB *sql.DB
}

// receipt is a partial mirror of the Rust treeship_core::session::SessionReceipt
// struct -- only the fields the Hub needs to extract for indexing. The full
// receipt body is round-tripped as JSON without re-serialization.
type receipt struct {
	Type    string         `json:"type"`
	Session sessionSection `json:"session"`
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

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body")
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

	// Idempotency: a second PUT from a DIFFERENT dock for the same session_id
	// is rejected so docks cannot squat on each other's session slots.
	existing, err := db.GetSession(h.DB, pathSessionID)
	if err == nil && existing != nil && existing.DockID != dockID {
		writeError(w, http.StatusForbidden, "session_id is owned by another dock")
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

	if err := db.UpsertSession(h.DB, sess); err != nil {
		log.Printf("upsert session error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to store receipt")
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

	receiptURL := "https://treeship.dev/receipt/" + pathSessionID

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
//   200 + receipt body  -- session exists, receipt is uploaded
//   403 "session still open"  -- session row exists, receipt_json is null
//   404 "session not found"   -- no row at all
func (h *Handlers) GetReceipt(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "session_id")
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "missing session_id in path")
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

// --- helpers ---

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
