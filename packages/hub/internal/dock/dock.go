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

// Authorized handles GET /v1/dock/authorized?device_code=XXX
func (h *Handlers) Authorized(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.URL.Query().Get("device_code")
	if deviceCode == "" || !isValidDeviceCode(deviceCode) {
		jsonError(w, "missing or invalid device_code", http.StatusBadRequest)
		return
	}

	challenge, err := db.GetChallenge(h.DB, deviceCode)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}

	if time.Now().Unix() > challenge.ExpiresAt {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "expired"})
		return
	}

	if !challenge.Approved {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
		return
	}

	// Challenge is approved. Return 200 with status "approved".
	w.Header().Set("Content-Type", "application/json")

	row := h.DB.QueryRow(
		`SELECT s.dock_id FROM ships s
		 JOIN dock_challenges dc ON dc.ship_public_key = s.ship_public_key AND dc.dock_public_key = s.dock_public_key
		 WHERE dc.device_code = ?`, challenge.DeviceCode,
	)
	var dockID string
	if err := row.Scan(&dockID); err != nil {
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"dock_id": dockID})
}

type authorizeRequest struct {
	ShipPublicKey string `json:"ship_public_key"`
	DockPublicKey string `json:"dock_public_key"`
	DeviceCode    string `json:"device_code"`
	Nonce         string `json:"nonce"`
}

// Authorize handles POST /v1/dock/authorize
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	if req.DeviceCode == "" || !isValidDeviceCode(req.DeviceCode) {
		jsonError(w, "missing or invalid device_code", http.StatusBadRequest)
		return
	}

	// Verify device_code exists and not expired.
	challenge, err := db.GetChallenge(h.DB, req.DeviceCode)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "device_code not found"})
		return
	}
	if time.Now().Unix() > challenge.ExpiresAt {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		json.NewEncoder(w).Encode(map[string]string{"error": "device_code expired"})
		return
	}

	// Browser-only approval (no keys): just mark as approved and return.
	if req.ShipPublicKey == "" || req.DockPublicKey == "" {
		if err := db.ApproveChallenge(h.DB, challenge.DeviceCode, nil, nil); err != nil {
			jsonError(w, "failed to approve challenge", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		return
	}

	// CLI flow: keys provided. Challenge MUST already be approved by browser.
	if !challenge.Approved {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "challenge not yet approved -- complete browser activation first"})
		return
	}

	// Nonce is mandatory for key-bearing finalization.
	if req.Nonce == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing nonce -- required for dock finalization"})
		return
	}
	if req.Nonce != challenge.Nonce {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "nonce mismatch"})
		return
	}

	// Atomically consume the challenge so concurrent requests cannot reuse it.
	consumed, err := db.ConsumeChallenge(h.DB, challenge.DeviceCode, challenge.Nonce)
	if err != nil || !consumed {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{"error": "challenge already consumed"})
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

	// Create the ship record.
	dockID := "dck_" + randomHex(16)
	now := time.Now().Unix()
	if err := db.InsertShip(h.DB, dockID, shipPubKey, dockPubKey, now); err != nil {
		jsonError(w, "failed to create ship", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"dock_id": dockID})
}

func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
