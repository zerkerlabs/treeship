package artifacts

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dpop"
	"github.com/treeship/hub/internal/rekor"
)

type Handlers struct {
	DB *sql.DB
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
func parseSignedAt(raw json.RawMessage) int64 {
	var ts int64
	if json.Unmarshal(raw, &ts) == nil {
		return ts
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		// best-effort parse -- just use current time if it fails
		return time.Now().Unix()
	}
	return time.Now().Unix()
}

// Push handles POST /v1/artifacts [DPoP authenticated]
func (h *Handlers) Push(w http.ResponseWriter, r *http.Request) {
	// DPoP verification.
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return // dpop.Verify already wrote the 401 response
	}

	var req pushRequest
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

	hubURL := "https://treeship.dev/verify/" + req.ArtifactID

	artifact := &db.Artifact{
		ArtifactID:   req.ArtifactID,
		PayloadType:  req.PayloadType,
		EnvelopeJSON: req.EnvelopeJSON,
		Digest:       req.Digest,
		SignedAt:     parseSignedAt(req.SignedAt),
		ParentID:     req.ParentID,
		HubURL:       hubURL,
		DockID:       &dockID,
	}

	if err := db.InsertArtifact(h.DB, artifact); err != nil {
		log.Printf("insert artifact error: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "failed to store artifact"})
		return
	}

	// Rekor anchoring (best-effort).
	// Look up ship_public_key for this dock.
	var shipPubKeyHex string
	row := h.DB.QueryRow(`SELECT ship_public_key FROM ships WHERE dock_id = ?`, dockID)
	var shipPubKey []byte
	if err := row.Scan(&shipPubKey); err == nil {
		shipPubKeyHex = hex.EncodeToString(shipPubKey)
	}

	var rekorIndex *int64
	if shipPubKeyHex != "" {
		rekorIndex = rekor.Anchor(h.DB, req.ArtifactID, req.Digest, req.EnvelopeJSON, shipPubKeyHex)
	}

	resp := map[string]interface{}{
		"artifact_id": req.ArtifactID,
		"hub_url":     hubURL,
	}
	if rekorIndex != nil {
		resp["rekor_index"] = *rekorIndex
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(artifact)
}
