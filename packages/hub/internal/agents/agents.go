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

	"github.com/treeship/hub/internal/db"
)

// receiptPayloadType is the MIME type of treeship receipt envelopes.
const receiptPayloadType = "application/vnd.treeship.receipt.v1+json"

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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"agent":        agent,
		"current_card": current,
		"cards":        cards,
		"revocations":  revocations,
		"note":         "raw signed envelopes; the client re-verifies and grades them offline. the Hub performs no verification or authorization here.",
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
