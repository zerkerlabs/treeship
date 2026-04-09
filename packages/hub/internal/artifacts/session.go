package artifacts

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dpop"
)

// workspaceSessionTTL is how long a minted share token stays valid.
// Kept short: the intended flow is "CLI mints, opens browser, browser loads
// workspace once, token is effectively single-use in practice".
const workspaceSessionTTL = 15 * time.Minute

// Session handles POST /v1/session
//
// DPoP-authenticated. The caller proves control of a dock's private key, and
// the Hub issues a short-lived opaque token scoped to that dock. The token
// can then be used by an unauthenticated browser context (for example, a
// share link opened by `treeship hub open`) to read the workspace via
// GET /v1/workspace/{dockId}?session=TOKEN.
func (h *Handlers) Session(w http.ResponseWriter, r *http.Request) {
	authedDockID := dpop.Verify(h.DB, w, r)
	if authedDockID == "" {
		return // dpop.Verify already wrote the 401 response
	}

	// Clean stale sessions opportunistically. Non-fatal if it fails.
	now := time.Now().Unix()
	_ = db.CleanExpiredWorkspaceSessions(h.DB, now)

	// 32 random bytes, base64url-encoded. ~43 chars, URL-safe.
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		log.Printf("session: rand.Read failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to generate token"})
		return
	}
	token := base64.RawURLEncoding.EncodeToString(raw[:])

	expiresAt := now + int64(workspaceSessionTTL.Seconds())
	if err := db.InsertWorkspaceSession(h.DB, token, authedDockID, now, expiresAt); err != nil {
		log.Printf("session: insert failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "failed to store session"})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"token":      token,
		"dock_id":    authedDockID,
		"expires_at": expiresAt,
	})
}
