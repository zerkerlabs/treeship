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

// makeActionEnvelope builds an envelope whose payload is an ActionStatement
// directly ({actor, action}), the way `attest action` produces it.
func makeActionEnvelope(t *testing.T, actor, action string) string {
	t.Helper()
	stmtBytes, _ := json.Marshal(map[string]any{"actor": actor, "action": action})
	env := map[string]any{
		"payload":     base64.RawURLEncoding.EncodeToString(stmtBytes),
		"payloadType": actionPayloadType,
		"signatures":  []map[string]string{{"keyid": "key_d", "sig": "AAAA"}},
	}
	envBytes, _ := json.Marshal(env)
	return string(envBytes)
}

func insertAction(t *testing.T, database *sql.DB, id, envJSON string, signedAt int64) {
	t.Helper()
	if err := db.InsertArtifact(database, &db.Artifact{
		ArtifactID:   id,
		PayloadType:  actionPayloadType,
		EnvelopeJSON: envJSON,
		Digest:       "sha256:00",
		SignedAt:     signedAt,
		HubURL:       "https://hub.test",
	}); err != nil {
		t.Fatalf("insert %s: %v", id, err)
	}
}

func TestLog_AgentHistory(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	insertAction(t, database, "art_a1", makeActionEnvelope(t, "agent://deployer", "file.write"), 100)
	insertAction(t, database, "art_a2", makeActionEnvelope(t, "agent://deployer", "db.query"), 200)
	insertAction(t, database, "art_ghost", makeActionEnvelope(t, "agent://ghost", "x"), 150)
	insertReceipt(t, database, "art_card",
		makeEnvelope(t, "agent_card.v1", map[string]any{
			"agent":           "agent://deployer",
			"keyid":           "key_d",
			"evidence_anchor": map[string]any{"receipt_count": 2},
		}, "key_d"), 300)

	h := &Handlers{DB: database}
	rec := httptest.NewRecorder()
	h.Log(rec, httptest.NewRequest(http.MethodGet, "/v1/agents/log?agent=agent://deployer", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (body %s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Entries         []logEntry             `json:"entries"`
		CommittedAnchor map[string]interface{} `json:"committed_anchor"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 2 actions + 1 card = 3 entries; ghost's action excluded.
	if len(body.Entries) != 3 {
		t.Errorf("entries = %d, want 3", len(body.Entries))
	}
	// Newest-first across kinds: the card (signed_at 300) is first.
	if len(body.Entries) > 0 && body.Entries[0].ArtifactID != "art_card" {
		t.Errorf("first entry = %s, want art_card (newest)", body.Entries[0].ArtifactID)
	}
	// No proof seeded, so every anchor is null.
	for _, e := range body.Entries {
		if e.MerkleAnchor != nil {
			t.Errorf("entry %s anchor = %v, want null", e.ArtifactID, e.MerkleAnchor)
		}
	}
	// The committed anchor is captured off the card.
	if body.CommittedAnchor["receipt_count"] != float64(2) {
		t.Errorf("committed_anchor = %v, want receipt_count 2", body.CommittedAnchor)
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
