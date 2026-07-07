package db

import (
	"path/filepath"
	"testing"
)

// InsertArtifact must be idempotent on artifact_id: artifacts are
// content-addressed, signed envelopes, so a re-push of the same id (an
// agent re-publishing its resolvable set on every boot) is the same bytes
// and must neither error nor overwrite what the hub already serves.
func TestInsertArtifactIdempotent(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	a := &Artifact{
		ArtifactID:   "art_test_dup",
		PayloadType:  "application/vnd.treeship.receipt+json",
		EnvelopeJSON: `{"payload":"original"}`,
		Digest:       "sha256:aaaa",
		SignedAt:     1,
		HubURL:       "https://api.example.dev",
	}
	if err := InsertArtifact(database, a); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Same id again — must not error (this used to bubble up as a PK
	// violation and a 500 to the pushing client).
	if err := InsertArtifact(database, a); err != nil {
		t.Fatalf("duplicate insert must be a no-op, got: %v", err)
	}

	// DO NOTHING, not DO UPDATE: a colliding id must never overwrite the
	// previously served bytes.
	mutated := *a
	mutated.EnvelopeJSON = `{"payload":"attacker-swapped"}`
	if err := InsertArtifact(database, &mutated); err != nil {
		t.Fatalf("conflicting insert must be a no-op, got: %v", err)
	}
	got, err := GetArtifact(database, "art_test_dup")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.EnvelopeJSON != `{"payload":"original"}` {
		t.Fatalf("stored envelope was overwritten: %q", got.EnvelopeJSON)
	}
}

// InsertCheckpoint must be idempotent on its natural key: re-running
// `merkle publish` re-POSTs the same checkpoint, and before the guard every
// re-publish inserted a duplicate row forever (autoincrement PK never
// collides). The repeat must return the ORIGINAL row's id.
func TestInsertCheckpointIdempotent(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	// Checkpoints reference a real dock — and with foreign keys now
	// actually enforced (PRAGMA foreign_keys=ON), a fabricated dock_id is
	// refused at the database, which this test also pins below.
	if err := InsertShip(database, "dck_cp", []byte("shippub"), []byte("dockpub"), 1); err != nil {
		t.Fatalf("insert ship: %v", err)
	}

	cp := &MerkleCheckpoint{
		RootHex: "ab12", TreeSize: 42, Height: 6,
		SignedAt: "2026-07-06T12:00:00Z", SignerKeyID: "key_s",
		SignatureB64: "sig", PublicKeyB64: "pub",
	}
	id1, err := InsertCheckpoint(database, cp, "dck_cp")
	if err != nil {
		t.Fatalf("first insert: %v", err)
	}
	id2, err := InsertCheckpoint(database, cp, "dck_cp")
	if err != nil {
		t.Fatalf("repeat insert: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("repeat must return the original id: %d vs %d", id1, id2)
	}

	// A genuinely different checkpoint (same signer, new size) still inserts.
	cp2 := *cp
	cp2.TreeSize = 43
	cp2.RootHex = "cd34"
	id3, err := InsertCheckpoint(database, &cp2, "dck_cp")
	if err != nil {
		t.Fatalf("new checkpoint insert: %v", err)
	}
	if id3 == id1 {
		t.Fatalf("distinct checkpoint must get a new row")
	}

	// Foreign keys are enforced: a checkpoint claiming a dock the hub has
	// never registered must be refused by the database itself.
	cp3 := *cp
	cp3.TreeSize = 44
	cp3.RootHex = "ef56"
	if _, err := InsertCheckpoint(database, &cp3, "dck_ghost"); err == nil {
		t.Fatalf("unknown dock_id must violate the foreign key")
	}
}
