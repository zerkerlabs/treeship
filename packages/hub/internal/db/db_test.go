package db

import (
	"database/sql"
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
	if _, err := InsertArtifact(database, a); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Same id again — must not error (this used to bubble up as a PK
	// violation and a 500 to the pushing client).
	if _, err := InsertArtifact(database, a); err != nil {
		t.Fatalf("duplicate insert must be a no-op, got: %v", err)
	}

	// DO NOTHING, not DO UPDATE: a colliding id must never overwrite the
	// previously served bytes.
	mutated := *a
	mutated.EnvelopeJSON = `{"payload":"attacker-swapped"}`
	if _, err := InsertArtifact(database, &mutated); err != nil {
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

// AUD-11: the consistency-proof `signer` field is free-form. DockOwnsCheckpointSigner
// is the predicate that binds it to the authenticated dock, so an attacker
// cannot squat a consistency row under a victim's signer.
func TestDockOwnsCheckpointSigner(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	if err := InsertShip(database, "dck_owner", []byte("s"), []byte("d"), 1); err != nil {
		t.Fatalf("insert owner ship: %v", err)
	}
	if err := InsertShip(database, "dck_attacker", []byte("s"), []byte("d"), 1); err != nil {
		t.Fatalf("insert attacker ship: %v", err)
	}
	cp := &MerkleCheckpoint{
		RootHex: "ab12", TreeSize: 10, Height: 4,
		SignedAt: "2026-07-06T12:00:00Z", SignerKeyID: "key_owner",
		SignatureB64: "sig", PublicKeyB64: "pub",
	}
	if _, err := InsertCheckpoint(database, cp, "dck_owner"); err != nil {
		t.Fatalf("insert checkpoint: %v", err)
	}

	// The owner published a checkpoint signed by key_owner.
	owns, err := DockOwnsCheckpointSigner(database, "dck_owner", "key_owner")
	if err != nil {
		t.Fatalf("ownership query: %v", err)
	}
	if !owns {
		t.Fatalf("owner must own its own signer")
	}
	// The attacker owns no checkpoint under key_owner — must be refused.
	owns, err = DockOwnsCheckpointSigner(database, "dck_attacker", "key_owner")
	if err != nil {
		t.Fatalf("ownership query: %v", err)
	}
	if owns {
		t.Fatalf("attacker must NOT be able to claim the victim's signer")
	}
}

// AUD-04: PublishProof's 403 keys on the checkpoint and artifact DockID. This
// pins that the stored ownership data is per-dock, so a proof-publish handler
// comparing *DockID == dockID rejects a cross-tenant artifact/checkpoint.
func TestCheckpointAndArtifactOwnershipIsPerDock(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	if err := InsertShip(database, "dck_a", []byte("s"), []byte("d"), 1); err != nil {
		t.Fatalf("ship a: %v", err)
	}
	if err := InsertShip(database, "dck_b", []byte("s"), []byte("d"), 1); err != nil {
		t.Fatalf("ship b: %v", err)
	}

	dockA := "dck_a"
	art := &Artifact{ArtifactID: "art_victim", PayloadType: "x", EnvelopeJSON: "{}", Digest: "sha256:a", SignedAt: 1, HubURL: "h", DockID: &dockA}
	if _, err := InsertArtifact(database, art); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}
	cp := &MerkleCheckpoint{RootHex: "ab", TreeSize: 1, Height: 1, SignedAt: "t", SignerKeyID: "k", SignatureB64: "s", PublicKeyB64: "p"}
	cpID, err := InsertCheckpoint(database, cp, dockA)
	if err != nil {
		t.Fatalf("insert checkpoint: %v", err)
	}

	gotArt, err := GetArtifact(database, "art_victim")
	if err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if gotArt.DockID == nil || *gotArt.DockID != "dck_a" {
		t.Fatalf("artifact owner must be dck_a, got %v", gotArt.DockID)
	}
	gotCP, err := GetCheckpoint(database, cpID)
	if err != nil {
		t.Fatalf("get checkpoint: %v", err)
	}
	if gotCP.DockID == nil || *gotCP.DockID != "dck_a" {
		t.Fatalf("checkpoint owner must be dck_a, got %v", gotCP.DockID)
	}
	// The handler compares these against the authenticated dockID: dck_b
	// publishing a proof over dck_a's artifact/checkpoint would see a
	// mismatch and 403.
	if gotArt.DockID != nil && *gotArt.DockID == "dck_b" {
		t.Fatalf("cross-tenant artifact must not read as dck_b's")
	}
}

// AUD-18: a signer id is bound to the public key its first checkpoint used.
// GetSignerPublicKey is the trust-on-first-use lookup the checkpoint handler
// gates on so a second dock cannot re-claim a victim's signer id with a
// different key.
func TestGetSignerPublicKeyFirstWriterBinding(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	if err := InsertShip(database, "dck_victim", []byte("s"), []byte("d"), 1); err != nil {
		t.Fatalf("insert ship: %v", err)
	}

	// Unknown signer: not found.
	_, found, err := GetSignerPublicKey(database, "key_sig")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if found {
		t.Fatal("an unseen signer must not be bound")
	}

	// Victim publishes first, binding key_sig -> PUBKEY_VICTIM.
	cp := &MerkleCheckpoint{
		RootHex: "ab12", TreeSize: 10, Height: 4,
		SignedAt: "2026-07-08T00:00:00Z", SignerKeyID: "key_sig",
		SignatureB64: "sig", PublicKeyB64: "PUBKEY_VICTIM",
	}
	if _, err := InsertCheckpoint(database, cp, "dck_victim"); err != nil {
		t.Fatalf("insert checkpoint: %v", err)
	}

	pub, found, err := GetSignerPublicKey(database, "key_sig")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if !found || pub != "PUBKEY_VICTIM" {
		t.Fatalf("signer must be bound to the first pubkey, got found=%v pub=%q", found, pub)
	}
	// The handler compares this against a later request's public_key: an
	// attacker presenting "PUBKEY_ATTACKER" for the same signer would mismatch
	// and be rejected.
	if pub == "PUBKEY_ATTACKER" {
		t.Fatal("binding must not resolve to an attacker key")
	}
}

// The schema production was created with in July 2026: artifacts without
// `kind`/`actor`, dock_challenges without `dock_id`. Copied verbatim from the
// deployed commit (ca9a4af2) rather than derived from `schema`, because a
// fixture derived from the current schema cannot represent a database that
// predates it -- which is the only database this test exists for.
const julySchema = `
CREATE TABLE IF NOT EXISTS ships (
  dock_id     TEXT PRIMARY KEY,
  public_key  BLOB NOT NULL,
  created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS artifacts (
  artifact_id   TEXT PRIMARY KEY,
  payload_type  TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  digest        TEXT NOT NULL,
  signed_at     INTEGER NOT NULL,
  parent_id     TEXT,
  hub_url       TEXT NOT NULL,
  rekor_index   INTEGER,
  dock_id       TEXT REFERENCES ships(dock_id)
);
CREATE TABLE IF NOT EXISTS dock_challenges (
  device_code     TEXT PRIMARY KEY,
  nonce           TEXT NOT NULL,
  expires_at      INTEGER NOT NULL,
  approved        INTEGER DEFAULT 0,
  dock_public_key BLOB,
  ship_public_key BLOB
);
CREATE INDEX IF NOT EXISTS idx_artifacts_payload_type ON artifacts(payload_type, signed_at);
CREATE INDEX IF NOT EXISTS idx_artifacts_dock_id ON artifacts(dock_id);
`

// Open must upgrade a database created before `kind`/`actor` existed.
//
// Regression: the derived-column indexes were part of `schema`, which runs
// before migrate() adds the columns, so Open failed with "apply schema: no
// such column: kind" on every pre-August database and succeeded on every
// fresh one. Production crash-looped on 2026-09-01. A test that only ever
// opens a fresh TempDir database cannot see this, so this one builds the
// old shape first.
func TestOpenUpgradesDatabaseCreatedBeforeDerivedColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	t.Setenv("TREESHIP_HUB_DB", path)

	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := old.Exec(julySchema); err != nil {
		t.Fatalf("create July schema: %v", err)
	}
	if _, err := old.Exec(
		`INSERT INTO artifacts (artifact_id, payload_type, envelope_json, digest, signed_at, hub_url)
		 VALUES ('art_old', 'application/vnd.treeship.action.v1+json', '{}', 'd', 1, 'https://api.treeship.dev')`,
	); err != nil {
		t.Fatalf("insert pre-migration row: %v", err)
	}
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}

	db, err := Open()
	if err != nil {
		t.Fatalf("Open on a July-shaped database: %v", err)
	}
	defer db.Close()

	// The columns arrived, the index that references them exists, and the
	// pre-existing row survived with kind unset ("not derived", not "no match").
	var kind *string
	if err := db.QueryRow(`SELECT kind FROM artifacts WHERE artifact_id = 'art_old'`).Scan(&kind); err != nil {
		t.Fatalf("read migrated row: %v", err)
	}
	if kind != nil {
		t.Fatalf("kind should be NULL on an un-backfilled row, got %q", *kind)
	}
	var n int
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name IN ('idx_artifacts_kind', 'idx_artifacts_actor_kind')`,
	).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("expected both derived indexes after upgrade, found %d", n)
	}

	// Opening again must be a no-op, not a second migration.
	db2, err := Open()
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	db2.Close()
}
