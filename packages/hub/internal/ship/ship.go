// Package ship implements per-ship registry endpoints:
//
//	GET /v1/ship/agents    (DPoP authenticated)
//	GET /v1/ship/sessions  (DPoP authenticated)
//
// Both return data scoped to the calling dock_id. There is no path parameter
// because the dock identity is established by the DPoP proof.
package ship

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	"github.com/treeship/hub/internal/auth"
	"github.com/treeship/hub/internal/db"
)

type Handlers struct {
	DB *sql.DB
}

// agentResponse is the public shape returned for each agent.
// Mirrors the spec: id, label, role, model, host, status.
type agentResponse struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	Role   string `json:"role,omitempty"`
	Model  string `json:"model,omitempty"`
	Host   string `json:"host,omitempty"`
	Status string `json:"status,omitempty"`
}

// sessionResponse is the public shape returned for each session.
type sessionResponse struct {
	SessionID   string  `json:"session_id"`
	Name        string  `json:"name,omitempty"`
	StartedAt   string  `json:"started_at,omitempty"`
	EndedAt     string  `json:"ended_at,omitempty"`
	DurationMin int64   `json:"duration_min"`
	Status      string  `json:"status"`
	AgentCount  int     `json:"agent_count"`
	ActionCount int     `json:"action_count"`
	ReceiptURL  string  `json:"receipt_url,omitempty"`
}

// ListAgents handles GET /v1/ship/agents.
//
// Accepts either DPoP (for CLI callers) or ?session=TOKEN (for browser
// callers loading a workspace share link). Returns the agent registry for
// the resolved dock. The registry is populated as a side-effect of
// PUT /v1/receipt: every receipt's agent_graph.nodes field upserts entries
// here. So a freshly registered ship that has never uploaded a receipt will
// get an empty list.
func (h *Handlers) ListAgents(w http.ResponseWriter, r *http.Request) {
	dockID := auth.ResolveReader(h.DB, w, r)
	if dockID == "" {
		return
	}

	rows, err := db.ListShipAgentsByDock(h.DB, dockID)
	if err != nil {
		log.Printf("list ship_agents error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to list agents")
		return
	}

	out := make([]agentResponse, 0, len(rows))
	for _, a := range rows {
		out = append(out, agentResponse{
			ID:     a.AgentID,
			Label:  derefOr(a.Label, a.AgentID),
			Role:   derefOr(a.Role, ""),
			Model:  derefOr(a.Model, ""),
			Host:   derefOr(a.Host, ""),
			Status: derefOr(a.Status, ""),
		})
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"agents": out,
	})
}

// ListSessions handles GET /v1/ship/sessions.
//
// Accepts either DPoP (for CLI callers) or ?session=TOKEN (for browser
// callers loading a workspace share link). Returns the resolved dock's
// session list, ordered most recent first (uploaded_at DESC, started_at
// DESC). Includes both closed sessions (with receipt_url) and open sessions
// (no receipt yet).
func (h *Handlers) ListSessions(w http.ResponseWriter, r *http.Request) {
	dockID := auth.ResolveReader(h.DB, w, r)
	if dockID == "" {
		return
	}

	rows, err := db.ListSessionsByDock(h.DB, dockID)
	if err != nil {
		log.Printf("list sessions error: %v", err)
		writeError(w, http.StatusInternalServerError, "failed to list sessions")
		return
	}

	out := make([]sessionResponse, 0, len(rows))
	for _, s := range rows {
		var durationMin int64
		if s.DurationMS != nil {
			durationMin = *s.DurationMS / 60000
		}

		entry := sessionResponse{
			SessionID:   s.SessionID,
			Name:        derefOr(s.Name, ""),
			StartedAt:   derefOr(s.StartedAt, ""),
			EndedAt:     derefOr(s.EndedAt, ""),
			DurationMin: durationMin,
			Status:      s.Status,
			AgentCount:  s.AgentCount,
			ActionCount: s.ActionCount,
		}
		if s.ReceiptJSON != nil && *s.ReceiptJSON != "" {
			entry.ReceiptURL = "https://treeship.dev/receipt/" + s.SessionID
		}
		out = append(out, entry)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": out,
	})
}

// --- helpers ---

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func derefOr(p *string, fallback string) string {
	if p == nil {
		return fallback
	}
	return *p
}
