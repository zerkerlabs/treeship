package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/treeship/hub/internal/contentaddress"
	"github.com/treeship/hub/internal/db"
)

// The endpoint this replaces returned a hardcoded empty list carrying a fresh
// `signed_at`, cached for 24 hours. These assert the three properties that
// made it wrong, rather than only that the new code runs.

func receiptEnvelope(t *testing.T, kind string, payload map[string]any) string {
	t.Helper()
	stmt, _ := json.Marshal(map[string]any{"kind": kind, "payload": payload})
	env, _ := json.Marshal(map[string]any{
		"payload":     base64.RawURLEncoding.EncodeToString(stmt),
		"payloadType": receiptPayloadType,
		"signatures":  []map[string]string{{"keyid": "k1", "sig": "AAAA"}},
	})
	return string(env)
}

func hubWith(t *testing.T, artifacts ...*db.Artifact) *http.ServeMux {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	if _, err := database.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at)
		 VALUES (?, ?, ?, ?)`, "dock_a", []byte("s"), []byte("d"), 1,
	); err != nil {
		t.Fatalf("register dock: %v", err)
	}
	for _, a := range artifacts {
		if _, err := db.InsertArtifact(database, a); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/treeship/revoked.json", revokedHandler(database))
	return mux
}

func getRevoked(t *testing.T, mux *http.ServeMux) (map[string]any, *httptest.ResponseRecorder) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/treeship/revoked.json", nil))
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, rec.Body.String())
	}
	return body, rec
}

// Mirrors what Push does: the indexed fields are derived from the envelope.
// A fixture that set them by hand would test the query and not the derivation.
func artifact(id, env string) *db.Artifact {
	dock := "dock_a"
	idx := contentaddress.DeriveIndexable(env)
	return &db.Artifact{
		Kind:         idx.Kind,
		Actor:        idx.Actor,
		ArtifactID:   id,
		PayloadType:  receiptPayloadType,
		EnvelopeJSON: env,
		Digest:       "sha256:00",
		SignedAt:     100,
		HubURL:       "https://treeship.dev/verify/" + id,
		DockID:       &dock,
	}
}

// The headline defect: the list was empty no matter what had been revoked.
func TestRevocationsActuallyAppear(t *testing.T) {
	env := receiptEnvelope(t, "grant_revocation.v1", map[string]any{
		"schema":     "grant_revocation.v1",
		"grant_id":   "grn_abc",
		"grantor":    "pk1",
		"revoked_at": "2026-08-14T10:00:00Z",
		"reason":     "compromised",
	})
	body, rec := getRevoked(t, hubWith(t, artifact("art_r1", env)))

	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	list, _ := body["revoked"].([]any)
	if len(list) != 1 {
		t.Fatalf("a revoked grant must appear in the list; got %d entries", len(list))
	}
	entry := list[0].(map[string]any)
	if entry["grant_id"] != "grn_abc" {
		t.Errorf("wrong grant_id: %v", entry["grant_id"])
	}
	// The evidence, not just the summary. A client that trusts the sibling
	// fields is trusting the hub; the envelope is what it verifies.
	if entry["envelope"] == nil {
		t.Error("entry carries no signed envelope, so a client has nothing to verify")
	}
}

// `signed_at` named a signature that did not exist. The hub holds no key and
// does not sign this list; saying otherwise invited clients to trust it.
func TestListDoesNotClaimToBeSigned(t *testing.T) {
	body, _ := getRevoked(t, hubWith(t))

	if _, present := body["signed_at"]; present {
		t.Error("`signed_at` implies a signature the hub cannot produce -- it holds no key")
	}
	if _, present := body["generated_at"]; !present {
		t.Error("the list should still say when it was produced")
	}
	note, _ := body["note"].(string)
	if note == "" {
		t.Error("the response must state that entries are individually signed and the list is not")
	}
}

// A day-long cache on a revocation list converts a revocation into a day-long
// grace period for whoever holds the revoked grant.
func TestCacheIsShortEnoughForRevocationToMeanSomething(t *testing.T) {
	_, rec := getRevoked(t, hubWith(t))
	cc := rec.Header().Get("Cache-Control")
	if cc == "max-age=86400" {
		t.Fatal("24h cache on a revocation list: a withdrawn grant reads as live for a day")
	}
	if cc == "" {
		t.Error("no Cache-Control at all leaves the window to whatever a proxy decides")
	}
}

// Only revocations. A hub serving every receipt here would leak unrelated
// records and bury the entries a client came for.
func TestOnlyGrantRevocationsAreListed(t *testing.T) {
	rev := receiptEnvelope(t, "grant_revocation.v1", map[string]any{
		"grant_id": "grn_abc", "grantor": "pk1", "revoked_at": "2026-08-14T10:00:00Z",
	})
	other := receiptEnvelope(t, "session.v1", map[string]any{"actor": "agent://x"})
	body, _ := getRevoked(t, hubWith(t, artifact("art_r1", rev), artifact("art_s1", other)))

	list, _ := body["revoked"].([]any)
	if len(list) != 1 {
		t.Fatalf("only grant_revocation.v1 belongs here; got %d entries", len(list))
	}
}

// An entry whose envelope will not decode cannot be verified by anyone.
// Emitting it with missing fields would put an unusable row on the list.
func TestUndecodableEnvelopesAreSkippedNotEmitted(t *testing.T) {
	body, rec := getRevoked(t, hubWith(t, artifact("art_bad", "{not json")))
	if rec.Code != http.StatusOK {
		t.Fatalf("one bad artifact must not fail the whole list: %d", rec.Code)
	}
	list, _ := body["revoked"].([]any)
	if len(list) != 0 {
		t.Fatalf("an undecodable envelope must not be listed; got %d", len(list))
	}
}

// Truncation has to be visible: a client that received a prefix and thought it
// had everything would honor fewer revocations than exist.
func TestTruncationIsReported(t *testing.T) {
	body, _ := getRevoked(t, hubWith(t))
	if _, present := body["truncated"]; !present {
		t.Error("`truncated` must always be present, so its absence is never ambiguous")
	}
}

// A hub upgraded in place holds artifacts written before `kind` existed. If
// the backfill does not run, every indexed query returns only what was
// ingested after the upgrade -- an empty revocation list on a hub that holds
// revocations, which is the worst shape of wrong answer: confident and wrong.
//
// This writes a row the way a pre-upgrade hub would (no derived fields), then
// asserts it is invisible until backfilled and present afterwards.
func TestBackfillMakesPreUpgradeRowsVisible(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at)
		 VALUES (?, ?, ?, ?)`, "dock_a", []byte("s"), []byte("d"), 1,
	); err != nil {
		t.Fatalf("register dock: %v", err)
	}

	env := receiptEnvelope(t, "grant_revocation.v1", map[string]any{
		"grant_id": "grn_old", "grantor": "pk1", "revoked_at": "2026-08-01T10:00:00Z",
	})
	// Deliberately NULL kind/actor -- exactly what a pre-migration row looks like.
	if _, err := database.Exec(
		`INSERT INTO artifacts
		 (artifact_id, payload_type, envelope_json, digest, signed_at, hub_url, dock_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"art_old", receiptPayloadType, env, "sha256:00", 100, "https://x/art_old", "dock_a",
	); err != nil {
		t.Fatalf("insert legacy row: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/treeship/revoked.json", revokedHandler(database))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/treeship/revoked.json", nil))
	var before map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &before)
	if list, _ := before["revoked"].([]any); len(list) != 0 {
		t.Fatalf("a row with no derived kind should not be found by an indexed query; got %d", len(list))
	}

	n, err := db.BackfillDerivedIndex(database, func(e string) (*string, *string) {
		idx := contentaddress.DeriveIndexable(e)
		return idx.Kind, idx.Actor
	})
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 1 {
		t.Fatalf("backfill should have updated 1 row, updated %d", n)
	}

	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/treeship/revoked.json", nil))
	var after map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	list, _ := after["revoked"].([]any)
	if len(list) != 1 {
		t.Fatalf("after backfill the legacy revocation must appear; got %d", len(list))
	}

	// Idempotent: a second run must not re-touch rows it already decided.
	n2, err := db.BackfillDerivedIndex(database, func(e string) (*string, *string) {
		idx := contentaddress.DeriveIndexable(e)
		return idx.Kind, idx.Actor
	})
	if err != nil || n2 != 0 {
		t.Fatalf("second backfill should be a no-op, got n=%d err=%v", n2, err)
	}
}

// The entries are individually signed, so this server cannot forge one. It
// CAN omit one, and an omitted revocation is indistinguishable from a grant
// nobody revoked -- the failure Certificate Transparency exists to detect.
//
// Completeness cannot be proven from a list. What the response must do is
// carry what a client needs to check inclusion for itself, and say plainly
// that absence proves nothing. A response that stayed silent on both would
// invite exactly the inference it cannot support.
func TestRevocationListShipsAnchorRefsAndDisclaimsCompleteness(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if _, err := database.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at)
		 VALUES (?, ?, ?, ?)`, "dock_a", []byte("s"), []byte("d"), 1,
	); err != nil {
		t.Fatalf("register dock: %v", err)
	}

	env := receiptEnvelope(t, "grant_revocation.v1", map[string]any{
		"grant_id": "grn_anchored", "grantor": "pk1", "revoked_at": "2026-08-01T10:00:00Z",
	})
	if _, err := db.InsertArtifact(database, artifact("art_anchored", env)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/treeship/revoked.json", revokedHandler(database))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/treeship/revoked.json", nil))

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("not JSON: %v", err)
	}

	note, _ := body["completeness"].(string)
	if !strings.Contains(note, "unproven") {
		t.Errorf("the response must say absence proves nothing; got %q", note)
	}

	list, _ := body["revoked"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected the revocation, got %d", len(list))
	}
	entry, _ := list[0].(map[string]any)

	// dock_id names the log to check inclusion against. Without it a client
	// cannot even form the request.
	if entry["dock_id"] != "dock_a" {
		t.Errorf("entry must name its dock log, got %v", entry["dock_id"])
	}
	// Present-and-null is the point: null means "not anchored", which a client
	// must be able to tell apart from the field being missing.
	if _, present := entry["rekor_index"]; !present {
		t.Error("rekor_index must be present even when null -- null means not anchored")
	}
	// And the signed bytes must still travel, or none of the above matters.
	if _, ok := entry["envelope"]; !ok {
		t.Error("the DSSE envelope is what makes an entry unforgeable; it must ship")
	}
}
