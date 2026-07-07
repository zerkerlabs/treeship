// Package agents implements the agent resolver: GET /v1/agents?agent=<uri>.
//
// It turns an agent URI into a verifiable bundle by scanning stored receipts
// for the agent's capability cards and revocations and returning the raw
// signed envelopes. The Hub does NO verification or grading here -- it serves
// bytes; the client re-verifies and grades them offline (`treeship resolve`).
// This keeps the trust decision on the client and avoids reimplementing the
// capability logic in Go, so the Hub and the CLI / WASM verifier cannot drift.
package agents

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"sort"

	"github.com/treeship/hub/internal/db"
)

// receiptPayloadType is the MIME type of treeship receipt envelopes.
const receiptPayloadType = "application/vnd.treeship.receipt.v1+json"

// actionPayloadType is the MIME type of treeship action envelopes.
const actionPayloadType = "application/vnd.treeship.action.v1+json"

type Handlers struct {
	DB *sql.DB
}

// dsseEnvelope is the minimal shape needed to read the statement + signer.
type dsseEnvelope struct {
	Payload    string `json:"payload"`
	Signatures []struct {
		KeyID string `json:"keyid"`
	} `json:"signatures"`
}

type receiptStatement struct {
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

// envelopeEntry is one raw signed artifact returned in the bundle. The client
// re-verifies it; the Hub asserts nothing about it beyond "this is what we hold".
type envelopeEntry struct {
	ArtifactID   string `json:"artifact_id"`
	EnvelopeJSON string `json:"envelope_json"`
	SignerKeyID  string `json:"signer_keyid"`
	SignedAt     int64  `json:"signed_at"`
}

// Resolve serves the verifiable bundle for an agent URI. Read-only and
// unauthenticated: resolving an identity is a public act, like a DNS query.
// The agent URI is taken as a query parameter (`?agent=agent://deployer`) so
// the `//` in the URI does not collide with path routing.
func (h *Handlers) Resolve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent query parameter"})
		return
	}

	receipts, err := db.ListArtifactsByPayloadType(h.DB, receiptPayloadType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	var cards []envelopeEntry
	var certs []envelopeEntry               // agent_cert.v1 chain for this agent
	revByCard := map[string]envelopeEntry{} // revoked card_id -> revocation entry
	cardIDs := map[string]bool{}            // this agent's card ids
	for _, a := range receipts {
		var env dsseEnvelope
		if json.Unmarshal([]byte(a.EnvelopeJSON), &env) != nil {
			continue
		}
		payloadBytes, decErr := base64.RawURLEncoding.DecodeString(env.Payload)
		if decErr != nil {
			continue
		}
		var stmt receiptStatement
		if json.Unmarshal(payloadBytes, &stmt) != nil {
			continue
		}
		signer := ""
		if len(env.Signatures) > 0 {
			signer = env.Signatures[0].KeyID
		}
		entry := envelopeEntry{a.ArtifactID, a.EnvelopeJSON, signer, a.SignedAt}

		switch stmt.Kind {
		case "agent_card.v1":
			var p struct {
				Agent string `json:"agent"`
			}
			if json.Unmarshal(stmt.Payload, &p) != nil || p.Agent != agent {
				continue
			}
			cards = append(cards, entry)
			cardIDs[a.ArtifactID] = true
		case "agent_card_revocation.v1":
			var p struct {
				Card string `json:"card"`
			}
			if json.Unmarshal(stmt.Payload, &p) != nil || p.Card == "" {
				continue
			}
			revByCard[p.Card] = entry
		case "agent_cert.v1":
			// The certificate chain: ship-signed bindings of this agent's
			// URI to its per-agent key. Served verbatim so a client that
			// pins only the ship key can walk card -> cert -> ship root.
			// The Hub does not verify them; the client decides.
			var p struct {
				Agent string `json:"agent"`
			}
			if json.Unmarshal(stmt.Payload, &p) != nil || p.Agent != agent {
				continue
			}
			certs = append(certs, entry)
		}
	}

	// receipts come newest-first, so the first matching card is the current one.
	var current *envelopeEntry
	if len(cards) > 0 {
		current = &cards[0]
	}

	// Include only revocations that reference one of this agent's cards. The
	// client decides whether each revocation is authorized; the Hub does not.
	var revocations []envelopeEntry
	for id := range cardIDs {
		if rev, ok := revByCard[id]; ok {
			revocations = append(revocations, rev)
		}
	}

	// Transparency: if the current card has a Merkle inclusion proof, include
	// it (the CLI's own ProofFile, stored verbatim) so the client can confirm
	// the card is in the log. Absent when the card has not been anchored.
	var transparency interface{}
	if current != nil {
		if proof, _, err := db.GetProof(h.DB, current.ArtifactID); err == nil && proof != nil {
			var pf interface{}
			if json.Unmarshal([]byte(proof.ProofJSON), &pf) == nil {
				transparency = pf
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":        agent,
		"current_card": current,
		"cards":        cards,
		"certs":        certs,
		"revocations":  revocations,
		"transparency": transparency,
		"note":         "raw signed envelopes; the client re-verifies and grades them offline. the Hub performs no verification or authorization here.",
	})
}

// actionStatement is the minimal shape needed to read an action's actor + label.
type actionStatement struct {
	Actor  string `json:"actor"`
	Action string `json:"action"`
}

// logEntry is one row of an agent's history: metadata + Merkle anchor, never
// the payload.
type logEntry struct {
	ArtifactID   string      `json:"artifact_id"`
	Kind         string      `json:"kind"`
	Actor        string      `json:"actor"`
	Action       string      `json:"action,omitempty"`
	SignedAt     int64       `json:"signed_at"`
	Digest       string      `json:"digest"`
	MerkleAnchor interface{} `json:"merkle_anchor"`
}

// decodeStatementPayload base64url-decodes an envelope's payload and returns
// the statement JSON bytes (and the signer keyid), or nil on any failure.
func decodeStatementPayload(envelopeJSON string) ([]byte, string) {
	var env dsseEnvelope
	if json.Unmarshal([]byte(envelopeJSON), &env) != nil {
		return nil, ""
	}
	b, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, ""
	}
	signer := ""
	if len(env.Signatures) > 0 {
		signer = env.Signatures[0].KeyID
	}
	return b, signer
}

// anchorFor returns the Merkle anchor for an artifact, or nil if not anchored.
func (h *Handlers) anchorFor(artifactID string) interface{} {
	proof, _, err := db.GetProof(h.DB, artifactID)
	if err != nil || proof == nil {
		return nil
	}
	return map[string]interface{}{
		"checkpoint_id": proof.CheckpointID,
		"leaf_index":    proof.LeafIndex,
	}
}

// Log serves an agent's append-only receipt history:
// GET /v1/agents/log?agent=<uri>. Metadata and Merkle anchors only, never
// payloads. The client re-verifies each anchored entry's inclusion and checks
// completeness against the agent's committed evidence_anchor.
func (h *Handlers) Log(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent query parameter"})
		return
	}

	var entries []logEntry
	var committed interface{}

	// Actions the agent performed.
	actions, err := db.ListArtifactsByPayloadType(h.DB, actionPayloadType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	for _, a := range actions {
		payload, _ := decodeStatementPayload(a.EnvelopeJSON)
		if payload == nil {
			continue
		}
		var stmt actionStatement
		if json.Unmarshal(payload, &stmt) != nil || stmt.Actor != agent {
			continue
		}
		entries = append(entries, logEntry{
			ArtifactID:   a.ArtifactID,
			Kind:         "action",
			Actor:        agent,
			Action:       stmt.Action,
			SignedAt:     a.SignedAt,
			Digest:       a.Digest,
			MerkleAnchor: h.anchorFor(a.ArtifactID),
		})
	}

	// Cards the agent published; capture the latest evidence_anchor as committed.
	receipts, err := db.ListArtifactsByPayloadType(h.DB, receiptPayloadType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}
	for _, a := range receipts {
		payload, _ := decodeStatementPayload(a.EnvelopeJSON)
		if payload == nil {
			continue
		}
		var stmt receiptStatement
		if json.Unmarshal(payload, &stmt) != nil || stmt.Kind != "agent_card.v1" {
			continue
		}
		var p struct {
			Agent          string      `json:"agent"`
			EvidenceAnchor interface{} `json:"evidence_anchor"`
		}
		if json.Unmarshal(stmt.Payload, &p) != nil || p.Agent != agent {
			continue
		}
		entries = append(entries, logEntry{
			ArtifactID:   a.ArtifactID,
			Kind:         "agent_card.v1",
			Actor:        agent,
			SignedAt:     a.SignedAt,
			Digest:       a.Digest,
			MerkleAnchor: h.anchorFor(a.ArtifactID),
		})
		// receipts come newest-first, so the first card's anchor is the current one.
		if committed == nil && p.EvidenceAnchor != nil {
			committed = p.EvidenceAnchor
		}
	}

	// Newest first across both kinds.
	sort.Slice(entries, func(i, j int) bool { return entries[i].SignedAt > entries[j].SignedAt })

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":            agent,
		"entries":          entries,
		"committed_anchor": committed,
		"note":             "metadata + Merkle anchors only, never payloads. the client re-verifies each anchored entry's inclusion and checks completeness against committed_anchor.",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// History handles GET /v1/agents/history?agent=<uri> — the work-history
// projection (docs/specs/work-history.md slice 2): the transparency log
// filtered to the agent's session.v1 records, served as raw signed envelopes
// plus Merkle anchors. The Hub filters and serves; the client re-verifies
// every envelope and every anchored entry's inclusion against its OWN trust
// roots and renders the typed fields itself — the Hub never interprets a
// record, so it cannot misrepresent one.
func (h *Handlers) History(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	agent := r.URL.Query().Get("agent")
	if agent == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing agent query parameter"})
		return
	}

	receipts, err := db.ListArtifactsByPayloadType(h.DB, receiptPayloadType)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "query failed"})
		return
	}

	type historyEntry struct {
		ArtifactID   string      `json:"artifact_id"`
		EnvelopeJSON string      `json:"envelope_json"`
		Signer       string      `json:"signer"`
		SignedAt     int64       `json:"signed_at"`
		MerkleAnchor interface{} `json:"merkle_anchor"`
	}
	var entries []historyEntry
	for _, a := range receipts {
		payload, _ := decodeStatementPayload(a.EnvelopeJSON)
		if payload == nil {
			continue
		}
		var stmt receiptStatement
		if json.Unmarshal(payload, &stmt) != nil || stmt.Kind != "session.v1" {
			continue
		}
		var p struct {
			Actor string `json:"actor"`
		}
		if json.Unmarshal(stmt.Payload, &p) != nil || p.Actor != agent {
			continue
		}
		var env dsseEnvelope
		signer := ""
		if json.Unmarshal([]byte(a.EnvelopeJSON), &env) == nil && len(env.Signatures) > 0 {
			signer = env.Signatures[0].KeyID
		}
		entries = append(entries, historyEntry{
			ArtifactID:   a.ArtifactID,
			EnvelopeJSON: a.EnvelopeJSON,
			Signer:       signer,
			SignedAt:     a.SignedAt,
			MerkleAnchor: h.anchorFor(a.ArtifactID),
		})
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].SignedAt > entries[j].SignedAt })

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":   agent,
		"entries": entries,
		"count":   len(entries),
		"note":    "raw signed session.v1 envelopes + Merkle anchors. the client re-verifies signatures and inclusion against its own trust roots; the Hub filters and serves, never interprets.",
	})
}
