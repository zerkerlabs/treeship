package dock

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
)

// newTestHandlers spins up an isolated SQLite-backed Handlers for one test.
func newTestHandlers(t *testing.T) *Handlers {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return &Handlers{DB: database}
}

func issueChallenge(t *testing.T, h *Handlers) (deviceCode, nonce string) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.Challenge(rec, httptest.NewRequest(http.MethodGet, "/v1/dock/challenge", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode challenge: %v", err)
	}
	if body["device_code"] == "" || body["nonce"] == "" {
		t.Fatalf("challenge missing device_code/nonce: %v", body)
	}
	return body["device_code"], body["nonce"]
}

func getAuthorized(t *testing.T, h *Handlers, code string) (int, map[string]interface{}) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/dock/authorized?device_code="+url.QueryEscape(code), nil)
	rec := httptest.NewRecorder()
	h.Authorized(rec, req)
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

func postAuthorize(t *testing.T, h *Handlers, payload map[string]string) (int, map[string]interface{}) {
	t.Helper()
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/v1/dock/authorize", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)
	var body map[string]interface{}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec.Code, body
}

// Two distinct, valid 32-byte hex keys for the CLI finalize step. The handler
// stores them verbatim; it does not validate them as curve points.
const (
	testShipPubHex = "abababababababababababababababababababababababababababababababab" + "ab"
	testDockPubHex = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd" + "cd"
)

func TestAuthorized_InvalidFormat(t *testing.T) {
	h := newTestHandlers(t)
	code, body := getAuthorized(t, h, "not-hex!")
	if code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", code)
	}
	if body["state"] != "invalid" {
		t.Fatalf("state = %v, want invalid", body["state"])
	}
}

func TestAuthorized_UnknownCode(t *testing.T) {
	h := newTestHandlers(t)
	// Well-formed but never issued.
	code, body := getAuthorized(t, h, strings.Repeat("a", 16))
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", code)
	}
	if body["state"] != "invalid" {
		t.Fatalf("state = %v, want invalid", body["state"])
	}
}

func TestAuthorized_Pending(t *testing.T) {
	h := newTestHandlers(t)
	code, _ := issueChallenge(t, h)
	status, body := getAuthorized(t, h, code)
	if status != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", status)
	}
	if body["state"] != "pending" {
		t.Fatalf("state = %v, want pending", body["state"])
	}
}

func TestAuthorized_Approved(t *testing.T) {
	h := newTestHandlers(t)
	code, _ := issueChallenge(t, h)

	// Browser approves with no keys.
	status, body := postAuthorize(t, h, map[string]string{"device_code": code})
	if status != http.StatusOK || body["state"] != "approved" {
		t.Fatalf("browser approve = %d %v, want 200 approved", status, body)
	}

	status, body = getAuthorized(t, h, code)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if body["state"] != "approved" {
		t.Fatalf("state = %v, want approved", body["state"])
	}
}

// TestAuthorized_AttachedNotNotFound is the regression test for the dogfooded
// "device_code not found then Attached" flash. After the CLI finalizes, the
// browser keeps polling /authorized. Previously the challenge row was deleted
// on consume, so the poll returned 404 "not found" even though attach
// succeeded. It must now report the terminal "attached" state.
func TestAuthorized_AttachedNotNotFound(t *testing.T) {
	h := newTestHandlers(t)
	code, nonce := issueChallenge(t, h)

	// Browser approval.
	if status, _ := postAuthorize(t, h, map[string]string{"device_code": code}); status != http.StatusOK {
		t.Fatalf("browser approve status = %d, want 200", status)
	}

	// CLI finalize with keys.
	status, body := postAuthorize(t, h, map[string]string{
		"device_code":     code,
		"ship_public_key": testShipPubHex,
		"dock_public_key": testDockPubHex,
		"nonce":           nonce,
	})
	if status != http.StatusOK {
		t.Fatalf("finalize status = %d, want 200", status)
	}
	if body["state"] != "attached" {
		t.Fatalf("finalize state = %v, want attached", body["state"])
	}
	dockID, _ := body["dock_id"].(string)
	if !strings.HasPrefix(dockID, "dck_") {
		t.Fatalf("dock_id = %q, want dck_ prefix", dockID)
	}

	// Browser still polling after finalize -- must see attached, not 404.
	pollStatus, pollBody := getAuthorized(t, h, code)
	if pollStatus != http.StatusOK {
		t.Fatalf("post-finalize poll status = %d, want 200 (regression: was 404)", pollStatus)
	}
	if pollBody["state"] != "attached" {
		t.Fatalf("post-finalize state = %v, want attached", pollBody["state"])
	}
	if pollBody["dock_id"] != dockID {
		t.Fatalf("post-finalize dock_id = %v, want %s", pollBody["dock_id"], dockID)
	}
}

// TestFinalize_SingleUse confirms the single-use invariant survives the switch
// from delete-on-consume to claim-by-dock_id: a second finalize is rejected and
// no second ship is minted.
func TestFinalize_SingleUse(t *testing.T) {
	h := newTestHandlers(t)
	code, nonce := issueChallenge(t, h)
	postAuthorize(t, h, map[string]string{"device_code": code})

	finalize := map[string]string{
		"device_code":     code,
		"ship_public_key": testShipPubHex,
		"dock_public_key": testDockPubHex,
		"nonce":           nonce,
	}

	status, first := postAuthorize(t, h, finalize)
	if status != http.StatusOK || first["state"] != "attached" {
		t.Fatalf("first finalize = %d %v, want 200 attached", status, first)
	}

	status, second := postAuthorize(t, h, finalize)
	if status != http.StatusConflict {
		t.Fatalf("second finalize status = %d, want 409", status)
	}
	if second["state"] != "already_attached" {
		t.Fatalf("second finalize state = %v, want already_attached", second["state"])
	}
}

func TestAuthorized_Expired(t *testing.T) {
	h := newTestHandlers(t)
	// Insert a challenge that is already expired. Format must pass validation.
	code := strings.Repeat("ab", 8) // 16 hex chars
	if err := db.InsertChallenge(h.DB, code, "deadbeef", time.Now().Unix()-10); err != nil {
		t.Fatalf("insert expired challenge: %v", err)
	}
	status, body := getAuthorized(t, h, code)
	if status != http.StatusGone {
		t.Fatalf("status = %d, want 410", status)
	}
	if body["state"] != "expired" {
		t.Fatalf("state = %v, want expired", body["state"])
	}
}

// TestAttachGuidanceProviderNeutral locks the provider-neutral contract: the
// canonical next_steps are placeholder templates (no customer baked in), while
// the single illustrative example may name ZMem.
func TestAttachGuidanceProviderNeutral(t *testing.T) {
	h := newTestHandlers(t)
	code, nonce := issueChallenge(t, h)
	postAuthorize(t, h, map[string]string{"device_code": code})
	_, body := postAuthorize(t, h, map[string]string{
		"device_code":     code,
		"ship_public_key": testShipPubHex,
		"dock_public_key": testDockPubHex,
		"nonce":           nonce,
	})

	steps, ok := body["next_steps"].([]interface{})
	if !ok || len(steps) == 0 {
		t.Fatalf("next_steps missing or empty: %v", body["next_steps"])
	}
	for _, s := range steps {
		if str, _ := s.(string); strings.Contains(str, "zmem") {
			t.Fatalf("next_steps must stay provider-neutral, found customer name: %q", str)
		}
	}
	wantCmds := []string{"treeship status", "treeship attest receipt", "treeship hub push", "treeship verify"}
	joined := strings.Join(toStrings(steps), "\n")
	for _, want := range wantCmds {
		if !strings.Contains(joined, want) {
			t.Fatalf("next_steps missing %q; got:\n%s", want, joined)
		}
	}
	example, _ := body["example"].(string)
	if !strings.Contains(example, "system://zmem") || !strings.Contains(example, "memory.proof") {
		t.Fatalf("example should illustrate the zmem memory-proof case, got %q", example)
	}
}

func toStrings(in []interface{}) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// AUD-30: /dock/authorize is unauthenticated and used to decode r.Body with no
// size cap, so a huge JSON value could OOM the hub. The MaxBytesReader must
// reject an oversized body instead of buffering it.
func TestAuthorizeRejectsOversizedBody(t *testing.T) {
	h := newTestHandlers(t)
	// A JSON body well over the 64 KiB cap.
	huge := `{"device_code":"` + strings.Repeat("A", 200*1024) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/dock/authorize", bytes.NewReader([]byte(huge)))
	rec := httptest.NewRecorder()
	h.Authorize(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized body must be rejected with 400, got %d", rec.Code)
	}
	// Fail-before-fix: with the MaxBytesReader cap the body is rejected at
	// DECODE ("invalid JSON body"). Without the cap the giant value decodes
	// fine and only fails later validation ("missing or invalid device_code")
	// — asserting the decode-path message proves the cap actually fired.
	var body map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body["error"] != "invalid JSON body" {
		t.Fatalf("expected rejection at decode (cap fired), got error=%q", body["error"])
	}
}
