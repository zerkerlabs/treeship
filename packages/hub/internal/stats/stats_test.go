package stats

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func insertShip(t *testing.T, database *sql.DB, dockID string, createdAt int64) {
	t.Helper()
	_, err := database.Exec(
		`INSERT INTO ships (dock_id, ship_public_key, dock_public_key, created_at) VALUES (?, ?, ?, ?)`,
		dockID, []byte{1}, []byte{2}, createdAt,
	)
	if err != nil {
		t.Fatalf("insert ship %s: %v", dockID, err)
	}
}

func insertArtifact(t *testing.T, database *sql.DB, id string, signedAt int64, dockID *string) {
	t.Helper()
	if err := db.InsertArtifact(database, &db.Artifact{
		ArtifactID:   id,
		PayloadType:  "application/vnd.treeship.action.v1+json",
		EnvelopeJSON: "{}",
		Digest:       "sha256:00",
		SignedAt:     signedAt,
		HubURL:       "https://hub.test",
		DockID:       dockID,
	}); err != nil {
		t.Fatalf("insert artifact %s: %v", id, err)
	}
}

func getStats(t *testing.T, database *sql.DB) response {
	t.Helper()
	h := &Handlers{DB: database}
	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rec := httptest.NewRecorder()
	h.Stats(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var resp response
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return resp
}

// The counts must reflect exactly what was inserted, split by the 7-day
// window: a wrong WHERE clause (or a vacuously-true one) fails on the
// old-row cases, and a too-strict one fails on the recent-row cases.
func TestStats_CountsSplitByWindow(t *testing.T) {
	database := openTestDB(t)

	now := time.Now().Unix()
	old := now - 30*24*3600 // 30 days ago, outside every 7d window

	// Docks: one attached long ago, one recent.
	insertShip(t, database, "dck_old", old)
	insertShip(t, database, "dck_new", now)

	// Artifacts: dck_old pushed one old artifact (attached but NOT active
	// in the window); dck_new pushed one recent; one recent artifact has
	// no dock at all and must count for artifacts but not for active docks.
	oldDock, newDock := "dck_old", "dck_new"
	insertArtifact(t, database, "art_old", old, &oldDock)
	insertArtifact(t, database, "art_new", now, &newDock)
	insertArtifact(t, database, "art_nodock", now, nil)

	// Sessions: one closed with a receipt uploaded recently, one still open.
	if _, err := database.Exec(
		`INSERT INTO sessions (session_id, dock_id, status, receipt_json, uploaded_at) VALUES (?, ?, 'closed', '{}', ?)`,
		"ssn_done", "dck_new", now,
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	if _, err := database.Exec(
		`INSERT INTO sessions (session_id, dock_id, status) VALUES (?, ?, 'open')`,
		"ssn_open", "dck_new",
	); err != nil {
		t.Fatalf("insert session: %v", err)
	}

	// Agents: same agent_id on two docks counts once (DISTINCT agent_id);
	// one agent last seen long ago drops out of the 7d window.
	for _, row := range []struct {
		dock, agent string
		lastSeen    int64
	}{
		{"dck_old", "agent://researcher", old},
		{"dck_new", "agent://researcher", now},
		{"dck_new", "agent://deployer", now},
	} {
		if _, err := database.Exec(
			`INSERT INTO ship_agents (dock_id, agent_id, last_seen) VALUES (?, ?, ?)`,
			row.dock, row.agent, row.lastSeen,
		); err != nil {
			t.Fatalf("insert ship_agent: %v", err)
		}
	}

	resp := getStats(t, database)

	assertEq(t, "artifacts.total", resp.Artifacts.Total, 3)
	assertEq(t, "artifacts.last_7d", resp.Artifacts.Last7d, 2)
	assertEq(t, "docks.total", resp.Docks.Total, 2)
	assertEq(t, "docks.attached_last_7d", resp.Docks.AttachedLast7d, 1)
	assertEq(t, "docks.active_last_7d", resp.Docks.ActiveLast7d, 1)
	assertEq(t, "sessions.total", resp.Sessions.Total, 2)
	assertEq(t, "sessions.receipts_uploaded", resp.Sessions.ReceiptsUploaded, 1)
	assertEq(t, "sessions.uploaded_last_7d", resp.Sessions.UploadedLast7d, 1)
	assertEq(t, "agents.total", resp.Agents.Total, 2)
	assertEq(t, "agents.seen_last_7d", resp.Agents.SeenLast7d, 2)

	if resp.GeneratedAt == "" {
		t.Error("generated_at is empty")
	}
}

func TestStats_EmptyDatabaseIsAllZeros(t *testing.T) {
	database := openTestDB(t)
	resp := getStats(t, database)
	for name, got := range map[string]int64{
		"artifacts.total": resp.Artifacts.Total,
		"docks.total":     resp.Docks.Total,
		"sessions.total":  resp.Sessions.Total,
		"agents.total":    resp.Agents.Total,
	} {
		if got != 0 {
			t.Errorf("%s = %d on empty database, want 0", name, got)
		}
	}
}

// A query failure must surface as 500, never as a zeros document: zeros on
// error read as "no adoption", a lie in the dangerous direction.
func TestStats_QueryFailureReturns500NotZeros(t *testing.T) {
	database := openTestDB(t)
	database.Close() // force every query to fail

	h := &Handlers{DB: database}
	req := httptest.NewRequest(http.MethodGet, "/v1/stats", nil)
	rec := httptest.NewRecorder()
	h.Stats(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body = %s", rec.Code, rec.Body.String())
	}
}

func assertEq(t *testing.T, name string, got, want int64) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %d, want %d", name, got, want)
	}
}
