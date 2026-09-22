package telemetry

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

const goodID = "ins_0123456789abcdef0123456789abcdef"

func goodPing() map[string]any {
	return map[string]any{
		"schema":      Schema,
		"install_id":  goodID,
		"event":       "install",
		"cli_version": "0.31.5",
		"os":          "macos",
		"arch":        "aarch64",
		"harness":     "claude-code",
	}
}

func post(t *testing.T, h *Handlers, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.Ingest(rec, req)
	return rec
}

func postJSON(t *testing.T, h *Handlers, v any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(v)
	return post(t, h, string(b))
}

func count(t *testing.T, database *sql.DB, q string) int64 {
	t.Helper()
	var n int64
	if err := database.QueryRow(q).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

// A valid ping is stored once as an install row and once as an event, and
// the response carries nothing back.
func TestIngestStoresInstallAndEvent(t *testing.T) {
	database := openTestDB(t)
	h := &Handlers{DB: database}

	rec := postJSON(t, h, goodPing())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body.String())
	}
	if rec.Body.Len() != 0 {
		t.Fatalf("204 must carry no body, got %q", rec.Body.String())
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_installs`); n != 1 {
		t.Fatalf("installs = %d, want 1", n)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_events`); n != 1 {
		t.Fatalf("events = %d, want 1", n)
	}
}

// Every field is checked. One bad field, one 400, and nothing stored.
func TestIngestRejectsEveryMalformedField(t *testing.T) {
	database := openTestDB(t)
	h := &Handlers{DB: database}

	bad := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"schema", func(m map[string]any) { m["schema"] = "treeship.telemetry.v0" }},
		{"install_id prefix", func(m map[string]any) { m["install_id"] = "ship_0123456789abcdef0123456789abcdef" }},
		{"install_id length", func(m map[string]any) { m["install_id"] = "ins_0123" }},
		{"install_id case", func(m map[string]any) { m["install_id"] = strings.ToUpper(goodID) }},
		{"event", func(m map[string]any) { m["event"] = "session.close" }},
		{"version", func(m map[string]any) { m["cli_version"] = "v0.31.5; DROP TABLE" }},
		{"version too long", func(m map[string]any) { m["cli_version"] = "0.31.5-" + strings.Repeat("a", 40) }},
		{"os", func(m map[string]any) { m["os"] = "Darwin 25.5.0" }},
		{"arch", func(m map[string]any) { m["arch"] = "arm64" }},
		{"harness", func(m map[string]any) { m["harness"] = "revaz-laptop" }},
		{"unknown field", func(m map[string]any) { m["hostname"] = "x" }},
		{"missing field", func(m map[string]any) { delete(m, "os") }},
	}
	for _, tc := range bad {
		m := goodPing()
		tc.mut(m)
		rec := postJSON(t, h, m)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", tc.name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), goodID) {
			t.Errorf("%s: response echoed the install id", tc.name)
		}
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_installs`); n != 0 {
		t.Fatalf("installs = %d after rejected pings, want 0", n)
	}
}

func TestIngestRejectsOversizeBodyAndWrongMethod(t *testing.T) {
	database := openTestDB(t)
	h := &Handlers{DB: database}

	rec := post(t, h, `{"schema":"`+Schema+`","pad":"`+strings.Repeat("x", MaxBody)+`"}`)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize: status %d, want 413", rec.Code)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/telemetry", nil)
	rec = httptest.NewRecorder()
	h.Ingest(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status %d, want 405", rec.Code)
	}

	// Two JSON documents in one body is not one ping.
	b, _ := json.Marshal(goodPing())
	rec = post(t, h, string(b)+string(b))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("trailing document: status %d, want 400", rec.Code)
	}
}

// A heartbeat inside the dedupe window is acknowledged and dropped; one
// after it is stored and moves last_seen. first_seen never moves, even when
// the client sends `install` again.
func TestRecordDedupesAndPreservesFirstSeen(t *testing.T) {
	database := openTestDB(t)
	t0 := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	p := &Ping{Schema: Schema, InstallID: goodID, Event: "install", CLIVersion: "0.31.5", OS: "linux", Arch: "x86_64", Harness: "unknown"}
	if err := Record(database, p, t0); err != nil {
		t.Fatal(err)
	}
	p.Event = "heartbeat"
	if err := Record(database, p, t0.Add(1*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_events`); n != 1 {
		t.Fatalf("events = %d after in-window heartbeat, want 1", n)
	}

	p.Event = "install" // wiped state file, same id restored from backup
	p.CLIVersion = "0.32.0"
	if err := Record(database, p, t0.Add(8*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var first, last int64
	var ver string
	if err := database.QueryRow(`SELECT first_seen, last_seen, cli_version FROM telemetry_installs WHERE install_id = ?`, goodID).
		Scan(&first, &last, &ver); err != nil {
		t.Fatal(err)
	}
	if first != t0.Unix() {
		t.Fatalf("first_seen moved: %d, want %d", first, t0.Unix())
	}
	if last != t0.Add(8*24*time.Hour).Unix() {
		t.Fatalf("last_seen = %d, want %d", last, t0.Add(8*24*time.Hour).Unix())
	}
	if ver != "0.32.0" {
		t.Fatalf("cli_version = %s, want the latest seen", ver)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_events`); n != 2 {
		t.Fatalf("events = %d, want 2", n)
	}
}

func TestSummarizeCountsWindows(t *testing.T) {
	database := openTestDB(t)
	now := time.Date(2026, 9, 22, 0, 0, 0, 0, time.UTC)
	seed := []struct {
		id      string
		first   time.Duration // ago
		last    time.Duration // ago
		harness string
	}{
		{"ins_" + strings.Repeat("a", 32), 60 * 24 * time.Hour, 60 * 24 * time.Hour, "unknown"},     // old, gone
		{"ins_" + strings.Repeat("b", 32), 20 * 24 * time.Hour, 2 * 24 * time.Hour, "claude-code"},  // new 30d, active 7d
		{"ins_" + strings.Repeat("c", 32), 3 * 24 * time.Hour, 3 * 24 * time.Hour, "codex"},         // new 7d, active 7d
		{"ins_" + strings.Repeat("d", 32), 45 * 24 * time.Hour, 10 * 24 * time.Hour, "claude-code"}, // active 30d only
	}
	for _, s := range seed {
		if _, err := database.Exec(`INSERT INTO telemetry_installs VALUES (?, ?, ?, '0.31.5', 'macos', 'aarch64', ?)`,
			s.id, now.Add(-s.first).Unix(), now.Add(-s.last).Unix(), s.harness); err != nil {
			t.Fatal(err)
		}
	}
	got, err := Summarize(database, now)
	if err != nil {
		t.Fatal(err)
	}
	want := Summary{Total: 4, New7d: 1, New30d: 2, Active7d: 2, Active30d: 3}
	if got.Total != want.Total || got.New7d != want.New7d || got.New30d != want.New30d ||
		got.Active7d != want.Active7d || got.Active30d != want.Active30d {
		t.Fatalf("summary = %+v, want counts %+v", got, want)
	}
	if got.ByHarness["claude-code"] != 2 || got.ByHarness["codex"] != 1 || got.ByHarness["unknown"] != 0 {
		t.Fatalf("by_harness = %v", got.ByHarness)
	}
	if got.Basis == "" {
		t.Fatal("summary must carry its basis caveat")
	}
}

// Rollup then purge: the day's numbers survive the deletion of the rows
// they were computed from, which is the whole point of the daily table.
func TestRollupSurvivesPurge(t *testing.T) {
	database := openTestDB(t)
	old := time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)
	for i, id := range []string{"ins_" + strings.Repeat("1", 32), "ins_" + strings.Repeat("2", 32)} {
		p := &Ping{Schema: Schema, InstallID: id, Event: "install", CLIVersion: "0.30.0", OS: "linux", Arch: "x86_64", Harness: "codex"}
		if err := Record(database, p, old.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	d, err := Rollup(database, old)
	if err != nil {
		t.Fatal(err)
	}
	if d.Day != "2026-05-01" || d.NewInstalls != 2 || d.ActiveInstalls != 2 || d.ByHarness["codex"] != 2 {
		t.Fatalf("rollup = %+v", d)
	}

	now := old.Add((RetentionDays + 1) * 24 * time.Hour)
	if err := Maintain(database, now); err != nil {
		t.Fatal(err)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_events`); n != 0 {
		t.Fatalf("events after purge = %d, want 0", n)
	}
	var active int64
	if err := database.QueryRow(`SELECT active_installs FROM telemetry_daily WHERE day = '2026-05-01'`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 2 {
		t.Fatalf("daily active after purge = %d, want 2", active)
	}
	if n := count(t, database, `SELECT COUNT(*) FROM telemetry_installs`); n != 2 {
		t.Fatalf("installs after purge = %d, want 2 (installs are permanent)", n)
	}
}
