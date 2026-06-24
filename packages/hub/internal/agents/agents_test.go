package agents

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/treeship/hub/internal/db"
)

// makeEnvelope builds an envelope_json wrapping a receipt statement, the way
// the CLI would: a base64url-no-pad payload over {kind, payload}, plus a signer.
func makeEnvelope(t *testing.T, kind string, payload map[string]any, signer string) string {
	t.Helper()
	stmtBytes, _ := json.Marshal(map[string]any{"kind": kind, "payload": payload})
	env := map[string]any{
		"payload":     base64.RawURLEncoding.EncodeToString(stmtBytes),
		"payloadType": receiptPayloadType,
		"signatures":  []map[string]string{{"keyid": signer, "sig": "AAAA"}},
	}
	envBytes, _ := json.Marshal(env)
	return string(envBytes)
}

func insertReceipt(t *testing.T, database *sql.DB, id, envJSON string, signedAt int64) {
	t.Helper()
	if err := db.InsertArtifact(database, &db.Artifact{
		ArtifactID:   id,
		PayloadType:  receiptPayloadType,
		EnvelopeJSON: envJSON,
		Digest:       "sha256:00",
		SignedAt:     signedAt,
		HubURL:       "https://hub.test",
	}); err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

func TestResolve_BundlesAgentCardsAndRevocations(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	// agent://deployer: an older card, a newer (current) card, a revocation of the new one.
	insertReceipt(t, database, "art_card_old",
		makeEnvelope(t, "agent_card.v1", map[string]any{"agent": "agent://deployer", "keyid": "key_d"}, "key_d"), 100)
	insertReceipt(t, database, "art_card_new",
		makeEnvelope(t, "agent_card.v1", map[string]any{"agent": "agent://deployer", "keyid": "key_d"}, "key_d"), 200)
	insertReceipt(t, database, "art_rev",
		makeEnvelope(t, "agent_card_revocation.v1", map[string]any{"card": "art_card_new"}, "key_d"), 300)
	// A different agent's card and a non-card receipt -> must be excluded.
	insertReceipt(t, database, "art_other",
		makeEnvelope(t, "agent_card.v1", map[string]any{"agent": "agent://ghost", "keyid": "key_g"}, "key_g"), 150)
	insertReceipt(t, database, "art_memproof",
		makeEnvelope(t, "memory.proof", map[string]any{"foo": "bar"}, "key_d"), 160)

	h := &Handlers{DB: database}
	rec := httptest.NewRecorder()
	h.Resolve(rec, httptest.NewRequest(http.MethodGet, "/v1/agents?agent=agent://deployer", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Agent        string          `json:"agent"`
		CurrentCard  *envelopeEntry  `json:"current_card"`
		Cards        []envelopeEntry `json:"cards"`
		Revocations  []envelopeEntry `json:"revocations"`
		Transparency interface{}     `json:"transparency"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// No Merkle proof was seeded, so transparency must be null (not anchored).
	if body.Transparency != nil {
		t.Errorf("transparency = %v, want null (no proof seeded)", body.Transparency)
	}

	if body.Agent != "agent://deployer" {
		t.Errorf("agent = %q", body.Agent)
	}
	// Newest deployer card is current.
	if body.CurrentCard == nil || body.CurrentCard.ArtifactID != "art_card_new" {
		t.Errorf("current_card = %+v, want art_card_new (newest)", body.CurrentCard)
	}
	// Only deployer's two cards; ghost's card and the memory.proof are excluded.
	if len(body.Cards) != 2 {
		t.Errorf("cards = %d, want 2", len(body.Cards))
	}
	// The revocation referencing a deployer card is included.
	if len(body.Revocations) != 1 || body.Revocations[0].ArtifactID != "art_rev" {
		t.Errorf("revocations = %+v, want [art_rev]", body.Revocations)
	}
}

func TestResolve_MissingAgentParam(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	h := &Handlers{DB: database}
	rec := httptest.NewRecorder()
	h.Resolve(rec, httptest.NewRequest(http.MethodGet, "/v1/agents", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
