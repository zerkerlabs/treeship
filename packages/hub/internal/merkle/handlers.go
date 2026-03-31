package merkle

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dpop"
)

type Handlers struct {
	DB *sql.DB
}

// --- POST /v1/merkle/checkpoint [DPoP authenticated] ---

type checkpointRequest struct {
	Root       string `json:"root"`
	TreeSize   int64  `json:"tree_size"`
	Height     int    `json:"height"`
	SignedAt   string `json:"signed_at"`
	Signer     string `json:"signer"`
	Signature  string `json:"signature"`
	PublicKey  string `json:"public_key"`
	RekorIndex *int64 `json:"rekor_index"`
	Index      int64  `json:"index"`
}

func (h *Handlers) PublishCheckpoint(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return
	}

	var req checkpointRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Root == "" || req.TreeSize == 0 || req.SignedAt == "" || req.Signer == "" || req.Signature == "" || req.PublicKey == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required checkpoint fields"})
		return
	}

	cp := &db.MerkleCheckpoint{
		RootHex:      req.Root,
		TreeSize:     req.TreeSize,
		Height:       req.Height,
		SignedAt:      req.SignedAt,
		SignerKeyID:   req.Signer,
		SignatureB64:  req.Signature,
		PublicKeyB64:  req.PublicKey,
		RekorIndex:    req.RekorIndex,
	}

	id, err := db.InsertCheckpoint(h.DB, cp, dockID)
	if err != nil {
		log.Printf("insert checkpoint error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store checkpoint"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":              id,
		"root":            req.Root,
		"hub_received_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// --- POST /v1/merkle/proof [DPoP authenticated] ---

type proofRequest struct {
	ArtifactID   string `json:"artifact_id"`
	CheckpointID int64  `json:"checkpoint_id"`
	LeafIndex    int64  `json:"leaf_index"`
	LeafHash     string `json:"leaf_hash"`
	ProofJSON    string `json:"proof_json"`
}

func (h *Handlers) PublishProof(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return
	}

	var req proofRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.ArtifactID == "" || req.CheckpointID == 0 || req.ProofJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required proof fields"})
		return
	}

	if err := db.InsertProof(h.DB, req.ArtifactID, req.CheckpointID, req.LeafIndex, req.LeafHash, req.ProofJSON, dockID); err != nil {
		log.Printf("insert proof error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store proof"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"artifact_id": req.ArtifactID,
		"stored":      true,
	})
}

// --- GET /v1/merkle/{artifactId} [public] ---

func (h *Handlers) GetProof(w http.ResponseWriter, r *http.Request) {
	artifactID := chi.URLParam(r, "artifactId")
	if artifactID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing artifact id"})
		return
	}

	proof, checkpoint, err := db.GetProof(h.DB, artifactID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proof not found"})
		return
	}

	// Return the full self-contained ProofFile JSON.
	// The proof_json field already contains the complete ProofFile serialized by the CLI.
	// We serve it directly so any client can verify offline.
	var proofFile interface{}
	if err := json.Unmarshal([]byte(proof.ProofJSON), &proofFile); err != nil {
		// Fallback: wrap proof + checkpoint manually
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"artifact_id":    proof.ArtifactID,
			"leaf_index":     proof.LeafIndex,
			"leaf_hash":      proof.LeafHash,
			"checkpoint_id":  proof.CheckpointID,
			"checkpoint":     checkpoint,
		})
		return
	}

	writeJSON(w, http.StatusOK, proofFile)
}

// --- GET /v1/merkle/checkpoint/{id} [public] ---

func (h *Handlers) GetCheckpoint(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid checkpoint id"})
		return
	}

	cp, err := db.GetCheckpoint(h.DB, id)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "checkpoint not found"})
		return
	}

	writeJSON(w, http.StatusOK, cp)
}

// --- GET /v1/merkle/checkpoint/latest [public] ---

func (h *Handlers) GetLatestCheckpoint(w http.ResponseWriter, r *http.Request) {
	dockID := r.URL.Query().Get("dock_id")

	cp, err := db.GetLatestCheckpoint(h.DB, dockID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no checkpoints found"})
		return
	}

	writeJSON(w, http.StatusOK, cp)
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
