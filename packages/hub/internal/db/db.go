package db

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS ships (
  dock_id         TEXT PRIMARY KEY,
  ship_public_key BLOB NOT NULL,
  dock_public_key BLOB NOT NULL,
  created_at      INTEGER NOT NULL
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

CREATE TABLE IF NOT EXISTS dpop_jtis (
  jti      TEXT PRIMARY KEY,
  seen_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS merkle_checkpoints (
  id              INTEGER PRIMARY KEY,
  root_hex        TEXT NOT NULL,
  tree_size       INTEGER NOT NULL,
  height          INTEGER NOT NULL,
  signed_at       TEXT NOT NULL,
  signer_key_id   TEXT NOT NULL,
  signature_b64   TEXT NOT NULL,
  public_key_b64  TEXT NOT NULL,
  rekor_index     INTEGER,
  dock_id         TEXT REFERENCES ships(dock_id)
);

CREATE TABLE IF NOT EXISTS merkle_proofs (
  artifact_id     TEXT NOT NULL,
  checkpoint_id   INTEGER NOT NULL REFERENCES merkle_checkpoints(id),
  leaf_index      INTEGER NOT NULL,
  leaf_hash       TEXT NOT NULL,
  proof_json      TEXT NOT NULL,
  dock_id         TEXT REFERENCES ships(dock_id),
  PRIMARY KEY (artifact_id, checkpoint_id)
);
`

// Open opens (or creates) the SQLite database and applies the schema.
func Open() (*sql.DB, error) {
	path := os.Getenv("TREESHIP_HUB_DB")
	if path == "" {
		path = "/tmp/treeship-hub.db"
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// WAL mode for better concurrency.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set WAL: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}

	return db, nil
}

// --- dock_challenges ---

type Challenge struct {
	DeviceCode string
	Nonce      string
	ExpiresAt  int64
	Approved   bool
	DockID     string // populated after authorize
}

func InsertChallenge(db *sql.DB, deviceCode, nonce string, expiresAt int64) error {
	_, err := db.Exec(
		`INSERT INTO dock_challenges (device_code, nonce, expires_at) VALUES (?, ?, ?)`,
		deviceCode, nonce, expiresAt,
	)
	return err
}

func GetChallenge(db *sql.DB, deviceCode string) (*Challenge, error) {
	// Support both full code (16 chars, from CLI polling) and short code (8 chars, from browser).
	query := `SELECT device_code, nonce, expires_at, approved FROM dock_challenges WHERE device_code = ?`
	args := []interface{}{deviceCode}
	if len(deviceCode) < 16 {
		query = `SELECT device_code, nonce, expires_at, approved FROM dock_challenges WHERE device_code LIKE ? ORDER BY expires_at DESC LIMIT 1`
		args = []interface{}{deviceCode + "%"}
	}
	row := db.QueryRow(query, args...)
	c := &Challenge{}
	var approved int
	if err := row.Scan(&c.DeviceCode, &c.Nonce, &c.ExpiresAt, &approved); err != nil {
		return nil, err
	}
	c.Approved = approved == 1
	return c, nil
}

func ApproveChallenge(db *sql.DB, deviceCode string, shipPubKey, dockPubKey []byte) error {
	// Support short code prefix match.
	query := `UPDATE dock_challenges SET approved = 1, ship_public_key = ?, dock_public_key = ? WHERE device_code = ?`
	args := []interface{}{shipPubKey, dockPubKey, deviceCode}
	if len(deviceCode) < 16 {
		query = `UPDATE dock_challenges SET approved = 1, ship_public_key = ?, dock_public_key = ? WHERE device_code LIKE ?`
		args = []interface{}{shipPubKey, dockPubKey, deviceCode + "%"}
	}
	_, err := db.Exec(query, args...)
	return err
}

// --- ships ---

func InsertShip(db *sql.DB, dockID string, shipPubKey, dockPubKey []byte, createdAt int64) error {
	_, err := db.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at) VALUES (?, ?, ?, ?)`,
		dockID, shipPubKey, dockPubKey, createdAt,
	)
	return err
}

func GetDockPublicKey(db *sql.DB, dockID string) ([]byte, error) {
	row := db.QueryRow(`SELECT dock_public_key FROM ships WHERE dock_id = ?`, dockID)
	var key []byte
	if err := row.Scan(&key); err != nil {
		return nil, err
	}
	return key, nil
}

// --- artifacts ---

type Artifact struct {
	ArtifactID   string  `json:"artifact_id"`
	PayloadType  string  `json:"payload_type"`
	EnvelopeJSON string  `json:"envelope_json"`
	Digest       string  `json:"digest"`
	SignedAt     int64   `json:"signed_at"`
	ParentID     *string `json:"parent_id"`
	HubURL       string  `json:"hub_url"`
	RekorIndex   *int64  `json:"rekor_index"`
	DockID       *string `json:"dock_id"`
}

func InsertArtifact(db *sql.DB, a *Artifact) error {
	_, err := db.Exec(
		`INSERT INTO artifacts (artifact_id, payload_type, envelope_json, digest, signed_at, parent_id, hub_url, rekor_index, dock_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ArtifactID, a.PayloadType, a.EnvelopeJSON, a.Digest, a.SignedAt, a.ParentID, a.HubURL, a.RekorIndex, a.DockID,
	)
	return err
}

func GetArtifact(db *sql.DB, artifactID string) (*Artifact, error) {
	row := db.QueryRow(
		`SELECT artifact_id, payload_type, envelope_json, digest, signed_at, parent_id, hub_url, rekor_index, dock_id
		 FROM artifacts WHERE artifact_id = ?`,
		artifactID,
	)
	a := &Artifact{}
	if err := row.Scan(&a.ArtifactID, &a.PayloadType, &a.EnvelopeJSON, &a.Digest, &a.SignedAt, &a.ParentID, &a.HubURL, &a.RekorIndex, &a.DockID); err != nil {
		return nil, err
	}
	return a, nil
}

// --- ships (query) ---

type Ship struct {
	DockID    string
	CreatedAt int64
}

func GetShip(db *sql.DB, dockID string) (*Ship, error) {
	row := db.QueryRow(`SELECT dock_id, created_at FROM ships WHERE dock_id = ?`, dockID)
	s := &Ship{}
	if err := row.Scan(&s.DockID, &s.CreatedAt); err != nil {
		return nil, err
	}
	return s, nil
}

func GetShipPublicKey(db *sql.DB, dockID string) (string, error) {
	var pubKey []byte
	err := db.QueryRow(`SELECT ship_public_key FROM ships WHERE dock_id = ?`, dockID).Scan(&pubKey)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(pubKey), nil
}

func ListArtifactsByDock(db *sql.DB, dockID string) ([]Artifact, error) {
	rows, err := db.Query(
		`SELECT artifact_id, payload_type, envelope_json, digest, signed_at, parent_id, hub_url, rekor_index, dock_id
		 FROM artifacts WHERE dock_id = ? ORDER BY signed_at DESC`, dockID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Artifact
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.ArtifactID, &a.PayloadType, &a.EnvelopeJSON, &a.Digest, &a.SignedAt, &a.ParentID, &a.HubURL, &a.RekorIndex, &a.DockID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func SetRekorIndex(db *sql.DB, artifactID string, logIndex int64) error {
	_, err := db.Exec(`UPDATE artifacts SET rekor_index = ? WHERE artifact_id = ?`, logIndex, artifactID)
	return err
}

// --- dpop_jtis ---

func InsertJTI(db *sql.DB, jti string, seenAt int64) error {
	_, err := db.Exec(`INSERT INTO dpop_jtis (jti, seen_at) VALUES (?, ?)`, jti, seenAt)
	return err
}

func JTIExists(db *sql.DB, jti string) (bool, error) {
	row := db.QueryRow(`SELECT COUNT(*) FROM dpop_jtis WHERE jti = ?`, jti)
	var count int
	if err := row.Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func CleanExpiredJTIs(db *sql.DB, before int64) error {
	_, err := db.Exec(`DELETE FROM dpop_jtis WHERE seen_at < ?`, before)
	return err
}

// --- merkle_checkpoints ---

type MerkleCheckpoint struct {
	ID            int64   `json:"id"`
	RootHex       string  `json:"root"`
	TreeSize      int64   `json:"tree_size"`
	Height        int     `json:"height"`
	SignedAt      string  `json:"signed_at"`
	SignerKeyID   string  `json:"signer"`
	SignatureB64  string  `json:"signature"`
	PublicKeyB64  string  `json:"public_key"`
	RekorIndex    *int64  `json:"rekor_index"`
	DockID        *string `json:"dock_id"`
}

func InsertCheckpoint(database *sql.DB, cp *MerkleCheckpoint, dockID string) (int64, error) {
	res, err := database.Exec(
		`INSERT INTO merkle_checkpoints (root_hex, tree_size, height, signed_at, signer_key_id, signature_b64, public_key_b64, rekor_index, dock_id)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cp.RootHex, cp.TreeSize, cp.Height, cp.SignedAt, cp.SignerKeyID, cp.SignatureB64, cp.PublicKeyB64, cp.RekorIndex, dockID,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func GetCheckpoint(database *sql.DB, id int64) (*MerkleCheckpoint, error) {
	row := database.QueryRow(
		`SELECT id, root_hex, tree_size, height, signed_at, signer_key_id, signature_b64, public_key_b64, rekor_index, dock_id
		 FROM merkle_checkpoints WHERE id = ?`, id,
	)
	cp := &MerkleCheckpoint{}
	if err := row.Scan(&cp.ID, &cp.RootHex, &cp.TreeSize, &cp.Height, &cp.SignedAt, &cp.SignerKeyID, &cp.SignatureB64, &cp.PublicKeyB64, &cp.RekorIndex, &cp.DockID); err != nil {
		return nil, err
	}
	return cp, nil
}

func GetLatestCheckpoint(database *sql.DB, dockID string) (*MerkleCheckpoint, error) {
	var row *sql.Row
	if dockID != "" {
		row = database.QueryRow(
			`SELECT id, root_hex, tree_size, height, signed_at, signer_key_id, signature_b64, public_key_b64, rekor_index, dock_id
			 FROM merkle_checkpoints WHERE dock_id = ? ORDER BY id DESC LIMIT 1`, dockID,
		)
	} else {
		row = database.QueryRow(
			`SELECT id, root_hex, tree_size, height, signed_at, signer_key_id, signature_b64, public_key_b64, rekor_index, dock_id
			 FROM merkle_checkpoints ORDER BY id DESC LIMIT 1`,
		)
	}
	cp := &MerkleCheckpoint{}
	if err := row.Scan(&cp.ID, &cp.RootHex, &cp.TreeSize, &cp.Height, &cp.SignedAt, &cp.SignerKeyID, &cp.SignatureB64, &cp.PublicKeyB64, &cp.RekorIndex, &cp.DockID); err != nil {
		return nil, err
	}
	return cp, nil
}

// --- merkle_proofs ---

type MerkleProof struct {
	ArtifactID   string `json:"artifact_id"`
	CheckpointID int64  `json:"checkpoint_id"`
	LeafIndex    int64  `json:"leaf_index"`
	LeafHash     string `json:"leaf_hash"`
	ProofJSON    string `json:"proof_json"`
	DockID       *string `json:"dock_id"`
}

func InsertProof(database *sql.DB, artifactID string, checkpointID int64, leafIndex int64, leafHash string, proofJSON string, dockID string) error {
	_, err := database.Exec(
		`INSERT OR REPLACE INTO merkle_proofs (artifact_id, checkpoint_id, leaf_index, leaf_hash, proof_json, dock_id)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		artifactID, checkpointID, leafIndex, leafHash, proofJSON, dockID,
	)
	return err
}

// GetProof looks up the proof for an artifact, joining with its checkpoint.
// Returns the full proof JSON (self-contained ProofFile) and the associated checkpoint.
func GetProof(database *sql.DB, artifactID string) (*MerkleProof, *MerkleCheckpoint, error) {
	row := database.QueryRow(
		`SELECT p.artifact_id, p.checkpoint_id, p.leaf_index, p.leaf_hash, p.proof_json, p.dock_id,
		        c.id, c.root_hex, c.tree_size, c.height, c.signed_at, c.signer_key_id, c.signature_b64, c.public_key_b64, c.rekor_index, c.dock_id
		 FROM merkle_proofs p
		 JOIN merkle_checkpoints c ON c.id = p.checkpoint_id
		 WHERE p.artifact_id = ?
		 ORDER BY p.checkpoint_id DESC LIMIT 1`, artifactID,
	)
	p := &MerkleProof{}
	cp := &MerkleCheckpoint{}
	if err := row.Scan(
		&p.ArtifactID, &p.CheckpointID, &p.LeafIndex, &p.LeafHash, &p.ProofJSON, &p.DockID,
		&cp.ID, &cp.RootHex, &cp.TreeSize, &cp.Height, &cp.SignedAt, &cp.SignerKeyID, &cp.SignatureB64, &cp.PublicKeyB64, &cp.RekorIndex, &cp.DockID,
	); err != nil {
		return nil, nil, err
	}
	return p, cp, nil
}
