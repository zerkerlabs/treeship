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

CREATE TABLE IF NOT EXISTS workspace_sessions (
  token       TEXT PRIMARY KEY,
  dock_id     TEXT NOT NULL REFERENCES ships(dock_id),
  created_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_workspace_sessions_expires_at ON workspace_sessions(expires_at);

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

-- Session metadata + uploaded receipts.
-- A row may exist with NULL receipt_json to represent a session that's
-- still open (registered but not yet closed). PUT /v1/receipt/:session_id
-- populates receipt_json and the closed-at fields.
CREATE TABLE IF NOT EXISTS sessions (
  session_id    TEXT PRIMARY KEY,
  dock_id       TEXT NOT NULL REFERENCES ships(dock_id),
  name          TEXT,
  started_at    TEXT,
  ended_at      TEXT,
  duration_ms   INTEGER,
  status        TEXT NOT NULL DEFAULT 'open',
  agent_count   INTEGER DEFAULT 0,
  action_count  INTEGER DEFAULT 0,
  receipt_json  TEXT,
  uploaded_at   INTEGER
);
CREATE INDEX IF NOT EXISTS idx_sessions_dock_id ON sessions(dock_id);
CREATE INDEX IF NOT EXISTS idx_sessions_uploaded_at ON sessions(uploaded_at);

-- Per-ship agent registry. Populated by extracting agent_graph.nodes
-- from uploaded session receipts. The (dock_id, agent_id) pair is the
-- composite key so the same agent identifier across two ships maps to
-- two distinct rows.
CREATE TABLE IF NOT EXISTS ship_agents (
  dock_id    TEXT NOT NULL REFERENCES ships(dock_id),
  agent_id   TEXT NOT NULL,
  label      TEXT,
  role       TEXT,
  model      TEXT,
  host       TEXT,
  status     TEXT,
  last_seen  INTEGER NOT NULL,
  PRIMARY KEY (dock_id, agent_id)
);
CREATE INDEX IF NOT EXISTS idx_ship_agents_dock_id ON ship_agents(dock_id);
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
	row := db.QueryRow(
		`SELECT device_code, nonce, expires_at, approved FROM dock_challenges WHERE device_code = ?`,
		deviceCode,
	)
	c := &Challenge{}
	var approved int
	if err := row.Scan(&c.DeviceCode, &c.Nonce, &c.ExpiresAt, &approved); err != nil {
		return nil, err
	}
	c.Approved = approved == 1
	return c, nil
}

func ApproveChallenge(db *sql.DB, deviceCode string, shipPubKey, dockPubKey []byte) error {
	_, err := db.Exec(
		`UPDATE dock_challenges SET approved = 1, ship_public_key = ?, dock_public_key = ? WHERE device_code = ?`,
		shipPubKey, dockPubKey, deviceCode,
	)
	return err
}

func DeleteChallenge(db *sql.DB, deviceCode string) error {
	_, err := db.Exec(`DELETE FROM dock_challenges WHERE device_code = ?`, deviceCode)
	return err
}

// ConsumeChallenge atomically deletes a challenge by device_code + nonce.
// Returns true if exactly one row was deleted (single-use guarantee).
func ConsumeChallenge(db *sql.DB, deviceCode string, nonce string) (bool, error) {
	result, err := db.Exec(
		`DELETE FROM dock_challenges WHERE device_code = ? AND nonce = ? AND approved = 1`,
		deviceCode, nonce,
	)
	if err != nil {
		return false, err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows == 1, nil
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

// --- workspace_sessions ---

// InsertWorkspaceSession stores a share token bound to a single dock_id.
func InsertWorkspaceSession(db *sql.DB, token, dockID string, createdAt, expiresAt int64) error {
	_, err := db.Exec(
		`INSERT INTO workspace_sessions (token, dock_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, dockID, createdAt, expiresAt,
	)
	return err
}

// GetWorkspaceSessionDockID returns the dock_id the token was issued for,
// if the token exists and is not yet expired.
func GetWorkspaceSessionDockID(db *sql.DB, token string, now int64) (string, error) {
	row := db.QueryRow(
		`SELECT dock_id FROM workspace_sessions WHERE token = ? AND expires_at > ?`,
		token, now,
	)
	var dockID string
	if err := row.Scan(&dockID); err != nil {
		return "", err
	}
	return dockID, nil
}

// CleanExpiredWorkspaceSessions purges sessions whose expiry has passed.
func CleanExpiredWorkspaceSessions(db *sql.DB, now int64) error {
	_, err := db.Exec(`DELETE FROM workspace_sessions WHERE expires_at <= ?`, now)
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

// --- sessions ---

// Session represents a row in the sessions table.
// ReceiptJSON is nil when the session is open (registered but no receipt yet).
type Session struct {
	SessionID    string
	DockID       string
	Name         *string
	StartedAt    *string
	EndedAt      *string
	DurationMS   *int64
	Status       string
	AgentCount   int
	ActionCount  int
	ReceiptJSON  *string
	UploadedAt   *int64
}

// InsertSessionWriteOnce atomically inserts a session with its receipt.
//
// Ownership rules:
//   - First insert wins: dock_id is never updated on conflict.
//   - Write-once receipt: receipt_json is set only if the existing row
//     has a NULL receipt. A second PUT with different content is rejected.
//   - Returns ("ok", nil) on successful insert or idempotent replay.
//   - Returns ("owned_by_other", nil) when the session_id belongs to
//     a different dock.
//   - Returns ("already_sealed", nil) when a receipt already exists
//     (same dock, but receipt_json is already non-NULL).
func InsertSessionWriteOnce(database *sql.DB, s *Session) (string, error) {
	// Attempt the insert. ON CONFLICT DO NOTHING so dock_id is never overwritten.
	res, err := database.Exec(
		`INSERT INTO sessions
		   (session_id, dock_id, name, started_at, ended_at, duration_ms, status, agent_count, action_count, receipt_json, uploaded_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(session_id) DO NOTHING`,
		s.SessionID, s.DockID, s.Name, s.StartedAt, s.EndedAt, s.DurationMS,
		s.Status, s.AgentCount, s.ActionCount, s.ReceiptJSON, s.UploadedAt,
	)
	if err != nil {
		return "", err
	}

	rows, _ := res.RowsAffected()
	if rows == 1 {
		// Fresh insert succeeded.
		return "ok", nil
	}

	// Row already exists. Check ownership and sealed state.
	existing, err := GetSession(database, s.SessionID)
	if err != nil {
		return "", err
	}
	if existing.DockID != s.DockID {
		return "owned_by_other", nil
	}
	if existing.ReceiptJSON != nil && *existing.ReceiptJSON != "" {
		// Already sealed. Accept only byte-identical replays.
		if s.ReceiptJSON != nil && *s.ReceiptJSON == *existing.ReceiptJSON {
			return "ok", nil
		}
		return "already_sealed", nil
	}

	// Same dock, receipt slot is empty. Fill it (write-once).
	// The WHERE clause guards against a concurrent write that sealed the
	// receipt between our GetSession and this UPDATE. We check RowsAffected
	// to detect the lost race and re-read to decide whether the winner's
	// content was identical (idempotent replay) or different (reject).
	res2, err := database.Exec(
		`UPDATE sessions SET
		   name = ?, started_at = ?, ended_at = ?, duration_ms = ?, status = ?,
		   agent_count = ?, action_count = ?, receipt_json = ?, uploaded_at = ?
		 WHERE session_id = ? AND dock_id = ? AND (receipt_json IS NULL OR receipt_json = '')`,
		s.Name, s.StartedAt, s.EndedAt, s.DurationMS, s.Status,
		s.AgentCount, s.ActionCount, s.ReceiptJSON, s.UploadedAt,
		s.SessionID, s.DockID,
	)
	if err != nil {
		return "", err
	}
	affected, _ := res2.RowsAffected()
	if affected == 0 {
		// Lost the race: another request sealed the receipt first. Re-read
		// to check if it was a byte-identical replay (ok) or a conflict.
		reread, err := GetSession(database, s.SessionID)
		if err != nil {
			return "", err
		}
		if reread.ReceiptJSON != nil && s.ReceiptJSON != nil && *reread.ReceiptJSON == *s.ReceiptJSON {
			return "ok", nil
		}
		return "already_sealed", nil
	}
	return "ok", nil
}

// GetSession returns a session row by session_id, or nil + sql.ErrNoRows if not found.
func GetSession(database *sql.DB, sessionID string) (*Session, error) {
	row := database.QueryRow(
		`SELECT session_id, dock_id, name, started_at, ended_at, duration_ms, status, agent_count, action_count, receipt_json, uploaded_at
		 FROM sessions WHERE session_id = ?`, sessionID,
	)
	s := &Session{}
	if err := row.Scan(
		&s.SessionID, &s.DockID, &s.Name, &s.StartedAt, &s.EndedAt, &s.DurationMS,
		&s.Status, &s.AgentCount, &s.ActionCount, &s.ReceiptJSON, &s.UploadedAt,
	); err != nil {
		return nil, err
	}
	return s, nil
}

// ListSessionsByDock returns all sessions for a dock, most recent first.
// Ordering uses uploaded_at DESC then started_at DESC as a tiebreaker.
func ListSessionsByDock(database *sql.DB, dockID string) ([]Session, error) {
	rows, err := database.Query(
		`SELECT session_id, dock_id, name, started_at, ended_at, duration_ms, status, agent_count, action_count, receipt_json, uploaded_at
		 FROM sessions WHERE dock_id = ?
		 ORDER BY COALESCE(uploaded_at, 0) DESC, COALESCE(started_at, '') DESC`,
		dockID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(
			&s.SessionID, &s.DockID, &s.Name, &s.StartedAt, &s.EndedAt, &s.DurationMS,
			&s.Status, &s.AgentCount, &s.ActionCount, &s.ReceiptJSON, &s.UploadedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// --- ship_agents ---

// ShipAgent represents a row in the ship_agents table.
type ShipAgent struct {
	DockID   string
	AgentID  string
	Label    *string
	Role     *string
	Model    *string
	Host     *string
	Status   *string
	LastSeen int64
}

// UpsertShipAgent inserts or updates an agent row for a given dock.
// Subsequent calls with the same (dock_id, agent_id) refresh the metadata
// fields and bump last_seen.
func UpsertShipAgent(database *sql.DB, a *ShipAgent) error {
	_, err := database.Exec(
		`INSERT INTO ship_agents
		   (dock_id, agent_id, label, role, model, host, status, last_seen)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(dock_id, agent_id) DO UPDATE SET
		   label     = excluded.label,
		   role      = excluded.role,
		   model     = excluded.model,
		   host      = excluded.host,
		   status    = excluded.status,
		   last_seen = excluded.last_seen`,
		a.DockID, a.AgentID, a.Label, a.Role, a.Model, a.Host, a.Status, a.LastSeen,
	)
	return err
}

// ListShipAgentsByDock returns all agents registered for a dock, most recently seen first.
func ListShipAgentsByDock(database *sql.DB, dockID string) ([]ShipAgent, error) {
	rows, err := database.Query(
		`SELECT dock_id, agent_id, label, role, model, host, status, last_seen
		 FROM ship_agents WHERE dock_id = ?
		 ORDER BY last_seen DESC`,
		dockID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ShipAgent
	for rows.Next() {
		var a ShipAgent
		if err := rows.Scan(
			&a.DockID, &a.AgentID, &a.Label, &a.Role, &a.Model, &a.Host, &a.Status, &a.LastSeen,
		); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
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
