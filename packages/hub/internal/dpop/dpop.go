package dpop

import (
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/treeship/hub/internal/db"
)

const maxClockSkew = 60 // seconds

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload struct {
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
}

// Verify checks the DPoP proof on the request and returns the dock_id on success.
// On failure it writes a 401 JSON response and returns an empty string.
func Verify(database *sql.DB, w http.ResponseWriter, r *http.Request) string {
	now := time.Now().Unix()

	// Clean expired JTIs (older than 5 minutes).
	_ = db.CleanExpiredJTIs(database, now-300)

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "DPoP ") {
		writeError(w, "missing or invalid Authorization header")
		return ""
	}
	dockID := strings.TrimPrefix(authHeader, "DPoP ")
	if dockID == "" {
		writeError(w, "missing dock_id in Authorization header")
		return ""
	}

	dpopHeader := r.Header.Get("DPoP")
	if dpopHeader == "" {
		writeError(w, "missing DPoP header")
		return ""
	}

	parts := strings.SplitN(dpopHeader, ".", 3)
	if len(parts) != 3 {
		writeError(w, "malformed DPoP JWT")
		return ""
	}

	// Decode header.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		writeError(w, "invalid DPoP header encoding")
		return ""
	}
	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		writeError(w, "invalid DPoP header JSON")
		return ""
	}
	if h.Alg != "EdDSA" || h.Typ != "dpop+jwt" {
		writeError(w, "unsupported DPoP algorithm or type")
		return ""
	}

	// Decode payload.
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		writeError(w, "invalid DPoP payload encoding")
		return ""
	}
	var p payload
	if err := json.Unmarshal(payloadBytes, &p); err != nil {
		writeError(w, "invalid DPoP payload JSON")
		return ""
	}

	// Check iat within 60 seconds.
	if abs(now-p.IAT) > maxClockSkew {
		writeError(w, "DPoP proof expired or clock skew too large")
		return ""
	}

	// Check jti uniqueness.
	seen, err := db.JTIExists(database, p.JTI)
	if err != nil {
		writeError(w, "internal error checking jti")
		return ""
	}
	if seen {
		writeError(w, "DPoP jti already used")
		return ""
	}

	// Check htm matches request method.
	if p.HTM != r.Method {
		writeError(w, fmt.Sprintf("DPoP htm mismatch: got %s, expected %s", p.HTM, r.Method))
		return ""
	}

	// Check htu matches request URL.
	// Build the full request URL for comparison.
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if fwd := r.Header.Get("X-Forwarded-Proto"); fwd != "" {
		scheme = fwd
	}
	requestURL := fmt.Sprintf("%s://%s%s", scheme, r.Host, r.URL.Path)
	if p.HTU != requestURL {
		writeError(w, fmt.Sprintf("DPoP htu mismatch: got %s, expected %s", p.HTU, requestURL))
		return ""
	}

	// Look up dock public key.
	pubKey, err := db.GetDockPublicKey(database, dockID)
	if err != nil {
		writeError(w, "dock_id not found")
		return ""
	}

	if len(pubKey) != ed25519.PublicKeySize {
		writeError(w, "invalid dock public key length")
		return ""
	}

	// Verify Ed25519 signature.
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		writeError(w, "invalid DPoP signature encoding")
		return ""
	}

	message := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(ed25519.PublicKey(pubKey), message, sigBytes) {
		writeError(w, "DPoP signature verification failed")
		return ""
	}

	// Record jti.
	if err := db.InsertJTI(database, p.JTI, now); err != nil {
		writeError(w, "internal error recording jti")
		return ""
	}

	return dockID
}

func writeError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
