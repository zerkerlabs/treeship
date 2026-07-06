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
