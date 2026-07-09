package merkle

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
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
	// AUD-18: the exact bytes the CLI's signature is computed over. The hub
	// ed25519-verifies against these rather than re-implementing the versioned
	// canonical in Go, then cross-checks that the structured fields above are
	// the ones actually signed.
	Canonical string `json:"canonical"`
}

func (h *Handlers) PublishCheckpoint(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return
	}

	var req checkpointRequest
	// Cap request body at 10 MB (same rule as receipts/artifacts).
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.Root == "" || req.TreeSize == 0 || req.SignedAt == "" || req.Signer == "" || req.Signature == "" || req.PublicKey == "" || req.Canonical == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required checkpoint fields"})
		return
	}

	// AUD-18: verify the checkpoint signature. Before this, the hub stored
	// signer/signature/public_key with NO verification, so anyone could POST a
	// checkpoint naming a victim's signer, which made DockOwnsCheckpointSigner
	// (the AUD-11 gate) return true for free and let the attacker shadow the
	// victim's consistency chain.
	if err := verifyCheckpointSignature(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Trust-on-first-use: a signer id is bound to the public key its first
	// checkpoint used. A later checkpoint claiming that signer with a different
	// key is rejected, so an attacker cannot re-claim a victim's signer id
	// (which is what would otherwise make the AUD-11 gate meaningless).
	boundPub, found, err := db.GetSignerPublicKey(h.DB, req.Signer)
	if err != nil {
		log.Printf("signer binding lookup error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to check signer binding"})
		return
	}
	if found && boundPub != req.PublicKey {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "signer is already bound to a different public key"})
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
	// Cap request body at 10 MB (same rule as receipts/artifacts).
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}

	if req.ArtifactID == "" || req.CheckpointID == 0 || req.ProofJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required proof fields"})
		return
	}

	// AUD-04: object-level authorization. Before this check, any authenticated
	// dock could publish a proof row keyed on (artifact_id, checkpoint_id) it
	// did not own. Because InsertProof is INSERT OR REPLACE and GetProof serves
	// the highest checkpoint_id, an attacker could shadow or destroy another
	// dock's inclusion proof so its anchored artifacts read as un-anchored.
	// Require the caller to own BOTH the artifact and the checkpoint the proof
	// binds them to.
	cp, err := db.GetCheckpoint(h.DB, req.CheckpointID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "checkpoint not found"})
		return
	}
	if cp.DockID == nil || *cp.DockID != dockID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "checkpoint is not owned by this dock"})
		return
	}
	art, err := db.GetArtifact(h.DB, req.ArtifactID)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "artifact not found"})
		return
	}
	if art.DockID == nil || *art.DockID != dockID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "artifact is not owned by this dock"})
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

// --- POST /v1/merkle/consistency [DPoP authenticated] ---
//
// Stores a client-computed consistency proof (transparency-log slice 3b). The
// Hub does not generate or verify it -- it holds no Merkle tree. The proof
// proves the tree at to_size extends the tree at from_size (append-only); the
// auditing client re-verifies offline against its own trust roots.

type consistencyRequest struct {
	Signer    string `json:"signer"`
	FromSize  int64  `json:"from_size"`
	FromRoot  string `json:"from_root"`
	ToSize    int64  `json:"to_size"`
	ToRoot    string `json:"to_root"`
	Version   int    `json:"version"`
	ProofJSON string `json:"proof_json"`
	SignedAt  string `json:"signed_at"`
}

func (h *Handlers) PublishConsistency(w http.ResponseWriter, r *http.Request) {
	dockID := dpop.Verify(h.DB, w, r)
	if dockID == "" {
		return
	}

	var req consistencyRequest
	// Cap request body at 10 MB (same rule as receipts/artifacts).
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if req.Signer == "" || req.FromRoot == "" || req.ToRoot == "" || req.ProofJSON == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing required consistency fields"})
		return
	}
	// A consistency proof only makes sense for a forward, non-empty extension.
	if req.FromSize <= 0 || req.ToSize < req.FromSize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "from_size must be > 0 and <= to_size"})
		return
	}

	// AUD-11: `signer` is free-form. Without this check an attacker could
	// pre-publish a bogus consistency row under a victim's signer and, since
	// InsertConsistency is first-writer-wins, permanently shadow the victim's
	// real transition. Bind the signer to the authenticated dock: the caller
	// must own a checkpoint signed by that signer.
	owns, err := db.DockOwnsCheckpointSigner(h.DB, dockID, req.Signer)
	if err != nil {
		log.Printf("consistency signer ownership check error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to verify signer ownership"})
		return
	}
	if !owns {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "signer is not owned by this dock"})
		return
	}

	c := &db.MerkleConsistency{
		Signer:    req.Signer,
		FromSize:  req.FromSize,
		FromRoot:  req.FromRoot,
		ToSize:    req.ToSize,
		ToRoot:    req.ToRoot,
		Version:   req.Version,
		ProofJSON: req.ProofJSON,
		SignedAt:  req.SignedAt,
	}
	id, err := db.InsertConsistency(h.DB, c, dockID)
	if err != nil {
		log.Printf("insert consistency error: %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to store consistency proof"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":              id,
		"hub_received_at": time.Now().UTC().Format(time.RFC3339),
	})
}

// --- GET /v1/merkle/consistency?signer=<>&from=<size> [public] ---
//
// Returns the consecutive consistency proofs for a signer from `from` onward --
// the chain an auditor walks from the checkpoint it last witnessed up to the
// latest, verifying each link offline.

func (h *Handlers) GetConsistency(w http.ResponseWriter, r *http.Request) {
	signer := r.URL.Query().Get("signer")
	if signer == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing signer"})
		return
	}
	var fromSize int64
	if s := r.URL.Query().Get("from"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid from size"})
			return
		}
		fromSize = v
	}

	chain, err := db.GetConsistencyChain(h.DB, signer, fromSize)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to read consistency chain"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"signer": signer,
		"from":   fromSize,
		"chain":  chain,
		"note":   "client-computed consistency proofs; the hub stores but never verifies them. re-verify each link offline against your trust roots.",
	})
}

// --- helpers ---

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// containsField reports whether want is an exact element of fields. Used to
// confirm a structured checkpoint field was one of the pipe-delimited values
// actually signed in the canonical string (AUD-18).
func containsField(fields []string, want string) bool {
	for _, f := range fields {
		if f == want {
			return true
		}
	}
	return false
}

// verifyCheckpointSignature ed25519-verifies a checkpoint publish request
// against its canonical bytes and cross-checks that the structured fields the
// hub will store were the ones actually signed (AUD-18). Returns nil on
// success or a client-safe error describing the first failure. It does NOT
// establish trust in the signer key — that is the signer→pubkey binding the
// caller enforces separately; this only proves the request is internally
// consistent and validly self-signed.
func verifyCheckpointSignature(req *checkpointRequest) error {
	pubKey, err := base64.RawURLEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return errCheckpoint("invalid public_key")
	}
	sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errCheckpoint("invalid signature")
	}
	if !ed25519.Verify(pubKey, []byte(req.Canonical), sig) {
		return errCheckpoint("checkpoint signature does not verify over the canonical bytes")
	}
	// The signature proves SOME key signed the canonical, but the canonical is
	// attacker-authored. Bind the stored structured fields to the SIGNED bytes:
	// each must appear as a pipe-delimited element of the canonical string, so
	// the hub cannot serve a signer/root/tree_size/signed_at that was not signed.
	canonFields := strings.Split(req.Canonical, "|")
	for _, want := range []string{req.Signer, req.Root, req.SignedAt, strconv.FormatInt(req.TreeSize, 10)} {
		if !containsField(canonFields, want) {
			return errCheckpoint("structured field not present in the signed canonical")
		}
	}
	return nil
}

type checkpointError string

func (e checkpointError) Error() string { return string(e) }
func errCheckpoint(msg string) error    { return checkpointError(msg) }
