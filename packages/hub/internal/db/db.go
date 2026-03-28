package db

import (
	"database/sql"
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
