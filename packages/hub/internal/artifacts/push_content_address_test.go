package artifacts

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/treeship/hub/internal/contentaddress"
	"github.com/treeship/hub/internal/db"
)

// These exercise the storage-layer consequences of the audit's P0-2 directly.
//
// The HTTP handler is gated behind DPoP, which needs a registered dock and a
// signed proof; setting that up here would mostly test dpop. What P0-2 was
// actually about is what ends up in the table, so these assert on that: an
// attacker's bytes must never become what an id serves, and a genuine re-push
// must stay idempotent.

func envelope(payloadType string, payload []byte) string {
	e, _ := json.Marshal(map[string]any{
		"payloadType": payloadType,
		"payload":     base64.RawURLEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{{"keyid": "k", "sig": "AAAA"}},
	})
	return string(e)
}

// honest builds an artifact whose declared identity actually matches its bytes.
func honest(t *testing.T, payloadType string, payload []byte, dock string) *db.Artifact {
	t.Helper()
	env := envelope(payloadType, payload)
	d, err := contentaddress.Derive(env)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	return &db.Artifact{
		ArtifactID:   d.ArtifactID,
		PayloadType:  d.PayloadType,
		EnvelopeJSON: env,
		Digest:       d.Digest,
		SignedAt:     100,
		HubURL:       "https://treeship.dev/verify/" + d.ArtifactID,
		DockID:       &dock,
	}
}

func openDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

// artifacts.dock_id REFERENCES ships(dock_id), and the schema's foreign keys
// are enforced, so ownership assertions need real rows behind them.
func registerDock(t *testing.T, database *sql.DB, dockID string) {
	t.Helper()
	if _, err := database.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at)
		 VALUES (?, ?, ?, ?)`,
		dockID, []byte("ship-pub"), []byte("dock-pub"), 1,
	); err != nil {
		t.Fatalf("register dock %s: %v", dockID, err)
	}
}

// The exploit: an authenticated dock claims a legitimate id for unrelated
// bytes. The derivation check must reject it before it ever reaches storage.
func TestAttackerCannotClaimAnotherArtifactsID(t *testing.T) {
	victim := honest(t, "application/vnd.treeship.action.v1+json",
		[]byte(`{"type":"treeship/action/v1","actor":"ship://victim"}`), "dock_victim")

	attackerBytes := envelope("application/vnd.treeship.action.v1+json",
		[]byte(`{"type":"treeship/action/v1","actor":"ship://attacker"}`))

	// What the handler does before touching the database.
	if _, err := contentaddress.Check(
		attackerBytes, victim.ArtifactID, victim.Digest, victim.PayloadType,
	); err == nil {
		t.Fatal("attacker bytes accepted under the victim's artifact id")
	}
}

// Before the fix, the loser of this race got a 200 and its bytes were dropped
// on the floor. Now the winner's bytes stay and the second push is visibly a
// duplicate rather than a silent no-op.
func TestFirstWriteWinsAndIsReportedAsSuchNotSilently(t *testing.T) {
	database := openDB(t)
	registerDock(t, database, "dock_a")
	a := honest(t, "application/vnd.treeship.action.v1+json",
		[]byte(`{"type":"treeship/action/v1","actor":"ship://a"}`), "dock_a")

	inserted, err := db.InsertArtifact(database, a)
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	if !inserted {
		t.Fatal("first insert of a new id reported as not inserted")
	}

	// Same artifact pushed again: idempotent, and the caller can tell.
	inserted, err = db.InsertArtifact(database, a)
	if err != nil {
		t.Fatalf("re-push: %v", err)
	}
	if inserted {
		t.Fatal("re-push reported as a fresh insert; the caller would re-anchor to Rekor")
	}

	stored, err := db.GetArtifact(database, a.ArtifactID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !contentaddress.SameBytes(stored.EnvelopeJSON, a.EnvelopeJSON) {
		t.Fatal("stored bytes changed across an idempotent re-push")
	}
}

// Defence in depth. With ids derived from bytes this needs a 128-bit SHA-256
// collision to reach, but the storage layer must not overwrite regardless --
// which is what stops a derivation bug from becoming a takeover.
func TestCollidingBytesNeverOverwriteWhatIsStored(t *testing.T) {
	database := openDB(t)
	registerDock(t, database, "dock_a")
	registerDock(t, database, "dock_attacker")
	original := honest(t, "application/vnd.treeship.action.v1+json",
		[]byte(`{"type":"treeship/action/v1","actor":"ship://original"}`), "dock_a")

	if _, err := db.InsertArtifact(database, original); err != nil {
		t.Fatalf("insert original: %v", err)
	}

	attackerDock := "dock_attacker"
	forged := *original
	forged.EnvelopeJSON = envelope("application/vnd.treeship.action.v1+json",
		[]byte(`{"type":"treeship/action/v1","actor":"ship://attacker"}`))
	forged.DockID = &attackerDock

	inserted, err := db.InsertArtifact(database, &forged)
	if err != nil {
		t.Fatalf("insert forged: %v", err)
	}
	if inserted {
		t.Fatal("forged bytes were inserted over an existing id")
	}

	stored, err := db.GetArtifact(database, original.ArtifactID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if stored.EnvelopeJSON != original.EnvelopeJSON {
		t.Fatal("stored envelope was replaced by the forged one")
	}
	if stored.DockID == nil || *stored.DockID != "dock_a" {
		t.Fatalf("ownership changed: got %v want dock_a", stored.DockID)
	}
	// The handler uses exactly this comparison to decide 409 vs idempotent.
	if contentaddress.SameBytes(stored.EnvelopeJSON, forged.EnvelopeJSON) {
		t.Fatal("differing envelopes compared equal; the handler would report success")
	}
}
