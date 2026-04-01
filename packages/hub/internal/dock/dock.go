package dock

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/treeship/hub/internal/db"
)

type Handlers struct {
	DB *sql.DB
}

// Challenge handles GET /v1/dock/challenge
func (h *Handlers) Challenge(w http.ResponseWriter, r *http.Request) {
	nonce := randomHex(16)
	deviceCode := randomHex(8)
	expiresAt := time.Now().Unix() + 300

	if err := db.InsertChallenge(h.DB, deviceCode, nonce, expiresAt); err != nil {
		http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
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
	if deviceCode == "" {
		http.Error(w, `{"error":"missing device_code"}`, http.StatusBadRequest)
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
	// The CLI will then POST /v1/dock/authorize with real keys to get a dock_id.
	// If a ships row already exists (CLI already called authorize), include dock_id.
	w.Header().Set("Content-Type", "application/json")

	row := h.DB.QueryRow(
		`SELECT s.dock_id FROM ships s
		 JOIN dock_challenges dc ON dc.ship_public_key = s.ship_public_key AND dc.dock_public_key = s.dock_public_key
		 WHERE dc.device_code = ?`, challenge.DeviceCode,
	)
	var dockID string
	if err := row.Scan(&dockID); err != nil {
		// No ships row yet -- browser approved but CLI hasn't sent keys
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"dock_id": dockID})
}

type authorizeRequest struct {
	ShipPublicKey string `json:"ship_public_key"`
	DockPublicKey string `json:"dock_public_key"`
	DeviceCode    string `json:"device_code"`
}

// Authorize handles POST /v1/dock/authorize
func (h *Handlers) Authorize(w http.ResponseWriter, r *http.Request) {
	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid JSON body"}`, http.StatusBadRequest)
		return
	}

	if req.DeviceCode == "" {
		http.Error(w, `{"error":"missing device_code"}`, http.StatusBadRequest)
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

	// Keys are optional for browser-initiated approval.
	// The CLI sends real keys in its own POST after polling detects approval.
	var shipPubKey, dockPubKey []byte
	if req.ShipPublicKey != "" {
		shipPubKey, err = hex.DecodeString(req.ShipPublicKey)
		if err != nil {
			http.Error(w, `{"error":"invalid ship_public_key hex"}`, http.StatusBadRequest)
			return
		}
	}
	if req.DockPublicKey != "" {
		dockPubKey, err = hex.DecodeString(req.DockPublicKey)
		if err != nil {
			http.Error(w, `{"error":"invalid dock_public_key hex"}`, http.StatusBadRequest)
			return
		}
	}

	// Mark the challenge as approved. The CLI will then POST with real keys.
	if err := db.ApproveChallenge(h.DB, challenge.DeviceCode, shipPubKey, dockPubKey); err != nil {
		http.Error(w, `{"error":"failed to approve challenge"}`, http.StatusInternalServerError)
		return
	}

	// Browser-only approval (no keys): just return approved status.
	// The CLI will call authorize again with real keys to get a dock_id.
	if len(shipPubKey) == 0 || len(dockPubKey) == 0 {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "approved"})
		return
	}

	// CLI flow: keys provided, create the ship record.
	dockID := "dck_" + randomHex(16)
	now := time.Now().Unix()
	if err := db.InsertShip(h.DB, dockID, shipPubKey, dockPubKey, now); err != nil {
		http.Error(w, `{"error":"failed to create ship"}`, http.StatusInternalServerError)
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
