package dock

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/treeship/hub/internal/db"
)

// isValidDeviceCode accepts both the full 16-char code and the legacy
// 8-char prefix format (from CLI v0.7.2 and earlier which displayed
// only the first 8 chars).
var deviceCodeRe = regexp.MustCompile(`^[0-9a-f]{8,16}$`)

func isValidDeviceCode(code string) bool {
	return deviceCodeRe.MatchString(code)
}

type Handlers struct {
	DB *sql.DB
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Challenge handles GET /v1/dock/challenge
func (h *Handlers) Challenge(w http.ResponseWriter, r *http.Request) {
	// Opportunistically purge challenges well past expiry. A 1-hour grace
	// window keeps recently-expired and recently-attached codes queryable so
	// in-flight activation pages still see a precise state. Mirrors the
	// per-request cleanup used for dpop_jtis and workspace_sessions.
	_ = db.CleanExpiredChallenges(h.DB, time.Now().Unix()-3600)

	nonce := randomHex(16)
	deviceCode := randomHex(8)
	expiresAt := time.Now().Unix() + 300

	if err := db.InsertChallenge(h.DB, deviceCode, nonce, expiresAt); err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"nonce":       nonce,
		"device_code": deviceCode,
		"expires_at":  fmt.Sprintf("%d", expiresAt),
	})
}

// writeJSON writes a JSON body with an explicit status code.
func writeJSON(w http.ResponseWriter, code int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// attachGuidance returns provider-neutral next steps shown after a device is
// attached. The commands use placeholders (<your-system>, <kind>, <file>,
// <artifact-id>) so the guidance describes Treeship behavior, not any one
// customer. `example` is a single illustrative invocation; ZMem is an example
// customer here, not built-in product behavior.
func attachGuidance() map[string]interface{} {
	return map[string]interface{}{
		"next_steps": []string{
			"treeship status",
			"treeship attest receipt --system system://<your-system> --kind <kind> --payload-file <file>",
			"treeship hub push <artifact-id>",
			"treeship verify <artifact-id>",
		},
		"example": "treeship attest receipt --system system://zmem --kind memory.proof --payload-file proof.json",
	}
}

// Authorized handles GET /v1/dock/authorized?device_code=XXX
//
// It reports a single, unambiguous `state` for the device code so the
// activation page can render distinct messaging instead of collapsing several
// outcomes into one "not found":
//
//	invalid  (400) malformed device_code
//	invalid  (404) no such challenge (never issued, or purged long after expiry)
//	attached (200) terminal success -- the CLI finalized; dock_id is present
//	expired  (410) the challenge passed its expiry window before being attached
//	pending  (202) issued, browser has not approved yet
//	approved (200) browser approved; the CLI has not finalized yet
//
// `attached` is checked before `expired` so a device that completed near the
// expiry boundary still reports success rather than flipping to expired.
func (h *Handlers) Authorized(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.URL.Query().Get("device_code")
	if deviceCode == "" || !isValidDeviceCode(deviceCode) {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"state": "invalid",
			"error": "missing or invalid device_code",
		})
		return
	}

	challenge, err := db.GetChallenge(h.DB, deviceCode)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"state": "invalid",
			"error": "unknown device code",
		})
		return
	}

	// Terminal success. Checked before expiry so a just-attached device near
	// the expiry boundary does not momentarily read as expired.
	if challenge.DockID != "" {
		body := map[string]interface{}{
			"state":   "attached",
			"dock_id": challenge.DockID,
		}
		for k, v := range attachGuidance() {
			body[k] = v
		}
		writeJSON(w, http.StatusOK, body)
		return
	}

	if time.Now().Unix() > challenge.ExpiresAt {
		writeJSON(w, http.StatusGone, map[string]string{
			"state": "expired",
			"error": "device code expired",
		})
		return
	}

	if !challenge.Approved {
		writeJSON(w, http.StatusAccepted, map[string]string{
			"state":  "pending",
			"status": "pending", // legacy field, kept for existing clients
		})
		return
	}

	// Browser approved; the CLI has not finalized yet. 200 so the CLI poll
	// loop (which breaks on HTTP 200) proceeds to the authorize step.
	writeJSON(w, http.StatusOK, map[string]string{
		"state":  "approved",
		"status": "approved", // legacy field, kept for existing clients
	})
}

type authorizeRequest struct {
	ShipPublicKey string `json:"ship_public_key"`
	DockPublicKey string `json:"dock_public_key"`
	DeviceCode    string `json:"device_code"`
	Nonce         string `json:"nonce"`
}

// Authorize handles POST /v1/dock/authorize
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	// AUD-30: cap the body before decoding. Every authenticated endpoint wraps
	// the body in MaxBytesReader; this UNauthenticated dock-finalize did not, so
	// a huge JSON string value buffered straight into memory (OOM, no auth
	// required). 64 KiB is ample for the device-code + two 32-byte pubkeys.
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.DeviceCode == "" || !isValidDeviceCode(req.DeviceCode) {
		jsonError(w, "missing or invalid device_code", http.StatusBadRequest)
		return
	}

	// Verify device_code exists.
	challenge, err := db.GetChallenge(h.DB, req.DeviceCode)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"state": "invalid",
			"error": "device_code not found",
		})
		return
	}

	// If the device was already finalized, report the terminal state instead
	// of a generic error. A browser that re-submits, or a duplicate CLI
	// finalize, lands here. This is the "already-used" case.
	if challenge.DockID != "" {
		writeJSON(w, http.StatusConflict, map[string]string{
			"state": "already_attached",
			"error": "device code already used",
		})
		return
	}

	if time.Now().Unix() > challenge.ExpiresAt {
		writeJSON(w, http.StatusGone, map[string]string{
			"state": "expired",
			"error": "device_code expired",
		})
		return
	}

	// Browser-only approval (no keys): just mark as approved and return.
	if req.ShipPublicKey == "" || req.DockPublicKey == "" {
		if err := db.ApproveChallenge(h.DB, challenge.DeviceCode, nil, nil); err != nil {
			jsonError(w, "failed to approve challenge", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"state":  "approved",
			"status": "approved", // legacy field, kept for existing clients
		})
		return
	}

	// CLI flow: keys provided. Challenge MUST already be approved by browser.
	if !challenge.Approved {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"state": "pending",
			"error": "challenge not yet approved -- complete browser activation first",
		})
		return
	}

	// Nonce is mandatory for key-bearing finalization.
	if req.Nonce == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing nonce -- required for dock finalization",
		})
		return
	}
	if req.Nonce != challenge.Nonce {
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "nonce mismatch",
		})
		return
	}

	shipPubKey, err := hex.DecodeString(req.ShipPublicKey)
	if err != nil {
		jsonError(w, "invalid ship_public_key hex", http.StatusBadRequest)
		return
	}
	dockPubKey, err := hex.DecodeString(req.DockPublicKey)
	if err != nil {
		jsonError(w, "invalid dock_public_key hex", http.StatusBadRequest)
		return
	}

	// Atomically claim the challenge for this dock_id. The claim is the
	// single-use gate: only one caller can transition an approved challenge
	// from unclaimed (dock_id NULL) to claimed, so concurrent or replayed
	// finalizes are rejected as "already used".
	dockID := "dck_" + randomHex(16)
	claimed, err := db.FinalizeChallenge(h.DB, challenge.DeviceCode, challenge.Nonce, dockID)
	if err != nil {
		jsonError(w, "failed to finalize challenge", http.StatusInternalServerError)
		return
	}
	if !claimed {
		writeJSON(w, http.StatusConflict, map[string]string{
			"state": "already_attached",
			"error": "device code already used",
		})
		return
	}

	// Create the ship record. If this fails, release the claim so the device
	// code is not stranded pointing at a ship that does not exist.
	now := time.Now().Unix()
	if err := db.InsertShip(h.DB, dockID, shipPubKey, dockPubKey, now); err != nil {
		_ = db.ReleaseChallenge(h.DB, challenge.DeviceCode, dockID)
		jsonError(w, "failed to create ship", http.StatusInternalServerError)
		return
	}

	body := map[string]interface{}{
		"state":   "attached",
		"dock_id": dockID,
	}
	for k, v := range attachGuidance() {
		body[k] = v
	}
	writeJSON(w, http.StatusOK, body)
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
