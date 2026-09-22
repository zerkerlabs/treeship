// Package telemetry ingests the CLI's anonymous usage pings and turns them
// into the adoption numbers `/v1/stats` reports.
//
//	POST /v1/telemetry  (public, no auth, rate limited)
//
// What arrives is one small JSON object per event: a random install id the
// CLI generated for itself, the event name (`install` or `heartbeat`), the CLI
// version, OS, architecture and harness. Nothing else is accepted: unknown
// fields are a 400, every value is checked against an allowlist or a narrow
// pattern, and the body is capped at 2 KiB. The client's own clock is not
// trusted; `received_at` is the hub's time.
//
// What is stored is exactly what arrived, plus the receive time, and never the
// request's IP, user agent or headers. The install id is random, is not a key,
// not a dock id and not derived from anything on the machine, so a row here
// answers "how many machines" and nothing about "which".
//
// Three tables: `telemetry_installs` (one row per install id, first and last
// seen, kept forever), `telemetry_events` (one row per accepted ping, purged
// after RetentionDays), and `telemetry_daily` (one row per UTC day with the
// counts, kept forever). The rollup is what makes the purge safe: the numbers
// outlive the rows they were computed from.
package telemetry

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// Schema is the only schema string the endpoint accepts.
const Schema = "treeship.telemetry.v1"

// RetentionDays is how long raw events are kept. Daily rollups and per-install
// first/last seen are permanent.
const RetentionDays = 90

// MaxBody caps the request body. A well-formed ping is under 300 bytes.
const MaxBody = 2048

// dedupeWindow: a heartbeat from an install already seen this recently is
// acknowledged and dropped. The CLI sends at most one a week; anything
// tighter is a replay or a bug, and either way one row a day is plenty.
const dedupeWindow = 20 * time.Hour

var (
	installIDPattern = regexp.MustCompile(`^ins_[0-9a-f]{32}$`)
	versionPattern   = regexp.MustCompile(`^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}(-[0-9A-Za-z.]{1,16})?$`)

	allowedEvents  = map[string]bool{"install": true, "heartbeat": true}
	allowedOS      = map[string]bool{"macos": true, "linux": true, "windows": true, "other": true}
	allowedArch    = map[string]bool{"x86_64": true, "aarch64": true, "other": true}
	allowedHarness = map[string]bool{"claude-code": true, "codex": true, "cursor": true, "unknown": true}
)

// Ping is the wire shape. Every field is required.
type Ping struct {
	Schema     string `json:"schema"`
	InstallID  string `json:"install_id"`
	Event      string `json:"event"`
	CLIVersion string `json:"cli_version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	Harness    string `json:"harness"`
}

// Validate checks every field against its allowlist or pattern. The error is
// generic on purpose: the response never echoes what was sent.
func (p *Ping) Validate() error {
	switch {
	case p.Schema != Schema:
		return errors.New("unsupported schema")
	case !installIDPattern.MatchString(p.InstallID):
		return errors.New("invalid install_id")
	case !allowedEvents[p.Event]:
		return errors.New("invalid event")
	case len(p.CLIVersion) > 32 || !versionPattern.MatchString(p.CLIVersion):
		return errors.New("invalid cli_version")
	case !allowedOS[p.OS]:
		return errors.New("invalid os")
	case !allowedArch[p.Arch]:
		return errors.New("invalid arch")
	case !allowedHarness[p.Harness]:
		return errors.New("invalid harness")
	}
	return nil
}

type Handlers struct {
	DB *sql.DB
	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// Ingest handles POST /v1/telemetry. 204 on accept (including a deduplicated
// heartbeat), 400 on anything malformed, 405 on the wrong method. The
// response body carries no information about stored state.
func (h *Handlers) Ingest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		http.Error(w, `{"error":"expected application/json"}`, http.StatusUnsupportedMediaType)
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBody))
	if err != nil {
		http.Error(w, `{"error":"body too large"}`, http.StatusRequestEntityTooLarge)
		return
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	var p Ping
	if err := dec.Decode(&p); err != nil {
		http.Error(w, `{"error":"invalid telemetry"}`, http.StatusBadRequest)
		return
	}
	if dec.More() {
		http.Error(w, `{"error":"invalid telemetry"}`, http.StatusBadRequest)
		return
	}
	if err := p.Validate(); err != nil {
		http.Error(w, `{"error":"invalid telemetry"}`, http.StatusBadRequest)
		return
	}

	if err := Record(h.DB, &p, h.now()); err != nil {
		// Logged without the payload: the log line must not become the
		// identifier store the tables were designed not to be.
		log.Printf("telemetry: record: %v", err)
		http.Error(w, `{"error":"telemetry unavailable"}`, http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Record upserts the install row and appends the event. A heartbeat from an
// install seen within dedupeWindow is dropped without a write. An `install`
// event for an id the hub already knows is treated as a heartbeat: the
// first_seen it already holds is the truth, and the client re-sending
// `install` (a wiped state file, a restored backup) must not move it.
func Record(db *sql.DB, p *Ping, now time.Time) error {
	ts := now.Unix()

	var lastSeen sql.NullInt64
	err := db.QueryRow(`SELECT last_seen FROM telemetry_installs WHERE install_id = ?`, p.InstallID).Scan(&lastSeen)
	switch {
	case err == sql.ErrNoRows:
		// New install.
	case err != nil:
		return fmt.Errorf("lookup: %w", err)
	default:
		if now.Sub(time.Unix(lastSeen.Int64, 0)) < dedupeWindow {
			return nil
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.Exec(`
		INSERT INTO telemetry_installs (install_id, first_seen, last_seen, cli_version, os, arch, harness)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(install_id) DO UPDATE SET
		  last_seen = excluded.last_seen,
		  cli_version = excluded.cli_version,
		  os = excluded.os,
		  arch = excluded.arch,
		  harness = excluded.harness`,
		p.InstallID, ts, ts, p.CLIVersion, p.OS, p.Arch, p.Harness); err != nil {
		return fmt.Errorf("upsert install: %w", err)
	}
	if _, err := tx.Exec(`
		INSERT INTO telemetry_events (install_id, event, cli_version, os, arch, harness, received_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.InstallID, p.Event, p.CLIVersion, p.OS, p.Arch, p.Harness, ts); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return tx.Commit()
}

// Summary is the block `/v1/stats` publishes. Counts only.
type Summary struct {
	Total     int64 `json:"total"`
	New7d     int64 `json:"new_7d"`
	New30d    int64 `json:"new_30d"`
	Active7d  int64 `json:"active_7d"`
	Active30d int64 `json:"active_30d"`
	// Breakdowns are over installs active in the last 30 days, so a version
	// nobody runs any more drops out on its own.
	ByVersion map[string]int64 `json:"by_version_30d"`
	ByHarness map[string]int64 `json:"by_harness_30d"`
	ByOS      map[string]int64 `json:"by_os_30d"`
	Basis     string           `json:"basis"`
}

// Basis is the caveat printed beside the numbers, in the same voice as the
// agents block: a reader must not mistake this for a verified population.
const Basis = "opt-out anonymous telemetry: one random id per machine, sent by the " +
	"CLI on first use and at most weekly after that, never in CI and never when " +
	"DO_NOT_TRACK or TREESHIP_NO_TELEMETRY is set. Machines that opted out are " +
	"not counted, so every number here is a floor."

// Summarize computes the Summary as of now.
func Summarize(db *sql.DB, now time.Time) (Summary, error) {
	s := Summary{
		ByVersion: map[string]int64{},
		ByHarness: map[string]int64{},
		ByOS:      map[string]int64{},
		Basis:     Basis,
	}
	c7 := now.Add(-7 * 24 * time.Hour).Unix()
	c30 := now.Add(-30 * 24 * time.Hour).Unix()

	counts := []struct {
		dst   *int64
		query string
		arg   int64
	}{
		{&s.Total, `SELECT COUNT(*) FROM telemetry_installs`, 0},
		{&s.New7d, `SELECT COUNT(*) FROM telemetry_installs WHERE first_seen >= ?`, c7},
		{&s.New30d, `SELECT COUNT(*) FROM telemetry_installs WHERE first_seen >= ?`, c30},
		{&s.Active7d, `SELECT COUNT(*) FROM telemetry_installs WHERE last_seen >= ?`, c7},
		{&s.Active30d, `SELECT COUNT(*) FROM telemetry_installs WHERE last_seen >= ?`, c30},
	}
	for _, c := range counts {
		var err error
		if c.arg == 0 {
			err = db.QueryRow(c.query).Scan(c.dst)
		} else {
			err = db.QueryRow(c.query, c.arg).Scan(c.dst)
		}
		if err != nil {
			return s, fmt.Errorf("%s: %w", c.query, err)
		}
	}

	for col, dst := range map[string]map[string]int64{
		"cli_version": s.ByVersion,
		"harness":     s.ByHarness,
		"os":          s.ByOS,
	} {
		// col is one of three literals owned by this function; never input.
		rows, err := db.Query(
			`SELECT `+col+`, COUNT(*) FROM telemetry_installs WHERE last_seen >= ? GROUP BY `+col, c30)
		if err != nil {
			return s, fmt.Errorf("breakdown %s: %w", col, err)
		}
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return s, fmt.Errorf("breakdown %s scan: %w", col, err)
			}
			dst[k] = n
		}
		rows.Close()
	}
	return s, nil
}

// Daily is one rolled-up UTC day.
type Daily struct {
	Day            string           `json:"day"`
	NewInstalls    int64            `json:"new_installs"`
	ActiveInstalls int64            `json:"active_installs"`
	ByVersion      map[string]int64 `json:"by_version"`
	ByHarness      map[string]int64 `json:"by_harness"`
	ByOS           map[string]int64 `json:"by_os"`
}

// Rollup computes and stores the row for the UTC day containing `at`.
// Idempotent: re-running for a day replaces its row, so a day can be
// recomputed for as long as its events are still retained.
func Rollup(db *sql.DB, at time.Time) (Daily, error) {
	day := at.UTC().Truncate(24 * time.Hour)
	start, end := day.Unix(), day.Add(24*time.Hour).Unix()
	d := Daily{
		Day:       day.Format("2006-01-02"),
		ByVersion: map[string]int64{},
		ByHarness: map[string]int64{},
		ByOS:      map[string]int64{},
	}
	if err := db.QueryRow(
		`SELECT COUNT(*) FROM telemetry_installs WHERE first_seen >= ? AND first_seen < ?`,
		start, end).Scan(&d.NewInstalls); err != nil {
		return d, fmt.Errorf("new installs: %w", err)
	}
	if err := db.QueryRow(
		`SELECT COUNT(DISTINCT install_id) FROM telemetry_events WHERE received_at >= ? AND received_at < ?`,
		start, end).Scan(&d.ActiveInstalls); err != nil {
		return d, fmt.Errorf("active installs: %w", err)
	}
	for col, dst := range map[string]map[string]int64{
		"cli_version": d.ByVersion,
		"harness":     d.ByHarness,
		"os":          d.ByOS,
	} {
		rows, err := db.Query(
			`SELECT `+col+`, COUNT(DISTINCT install_id) FROM telemetry_events
			 WHERE received_at >= ? AND received_at < ? GROUP BY `+col, start, end)
		if err != nil {
			return d, fmt.Errorf("rollup %s: %w", col, err)
		}
		for rows.Next() {
			var k string
			var n int64
			if err := rows.Scan(&k, &n); err != nil {
				rows.Close()
				return d, fmt.Errorf("rollup %s scan: %w", col, err)
			}
			dst[k] = n
		}
		rows.Close()
	}

	bv, _ := json.Marshal(d.ByVersion)
	bh, _ := json.Marshal(d.ByHarness)
	bo, _ := json.Marshal(d.ByOS)
	if _, err := db.Exec(`
		INSERT INTO telemetry_daily (day, new_installs, active_installs, by_version, by_harness, by_os, computed_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(day) DO UPDATE SET
		  new_installs = excluded.new_installs,
		  active_installs = excluded.active_installs,
		  by_version = excluded.by_version,
		  by_harness = excluded.by_harness,
		  by_os = excluded.by_os,
		  computed_at = excluded.computed_at`,
		d.Day, d.NewInstalls, d.ActiveInstalls, string(bv), string(bh), string(bo), time.Now().Unix()); err != nil {
		return d, fmt.Errorf("store rollup: %w", err)
	}
	return d, nil
}

// Purge deletes raw events older than RetentionDays. Rollup first, purge
// second: Maintain enforces that order so a day is never lost unrolled.
func Purge(db *sql.DB, now time.Time) (int64, error) {
	cutoff := now.Add(-RetentionDays * 24 * time.Hour).Unix()
	res, err := db.Exec(`DELETE FROM telemetry_events WHERE received_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Maintain runs one maintenance pass: roll up yesterday and today, then purge.
// Yesterday is recomputed because the previous pass may have run before the
// day was over.
func Maintain(db *sql.DB, now time.Time) error {
	for _, at := range []time.Time{now.Add(-24 * time.Hour), now} {
		if _, err := Rollup(db, at); err != nil {
			return err
		}
	}
	if _, err := Purge(db, now); err != nil {
		return fmt.Errorf("purge: %w", err)
	}
	return nil
}

// StartMaintenance runs Maintain now and then every interval until stop is
// closed. Errors are logged, never fatal: a failed rollup is a stale number,
// not a reason to take the hub down.
func StartMaintenance(db *sql.DB, interval time.Duration, stop <-chan struct{}) {
	run := func() {
		if err := Maintain(db, time.Now()); err != nil {
			log.Printf("telemetry: maintenance: %v", err)
		}
	}
	go func() {
		run()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				run()
			case <-stop:
				return
			}
		}
	}()
}
