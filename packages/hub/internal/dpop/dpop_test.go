package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
)

// The DPoP verifier is the hub's entire authentication boundary — every
// authenticated write (artifacts, checkpoints, proofs, receipts) funnels
// through Verify. These tests pin the accept path and every rejection
// branch with real Ed25519 keys, so a regression here is a failing test,
// not a silent auth bypass.

type testDock struct {
	dockID string
	priv   ed25519.PrivateKey
}

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func registerDock(t *testing.T, database *sql.DB, dockID string) testDock {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := db.InsertShip(database, dockID, pub, pub, time.Now().Unix()); err != nil {
		t.Fatalf("insert ship: %v", err)
	}
	return testDock{dockID: dockID, priv: priv}
}

type proofOpts struct {
	alg    string
	typ    string
	iat    int64
	jti    string
	htm    string
	htu    string
	signer ed25519.PrivateKey // overrides the dock's key when set
}

func (d testDock) proof(t *testing.T, opts proofOpts) string {
	t.Helper()
	if opts.alg == "" {
		opts.alg = "EdDSA"
	}
	if opts.typ == "" {
		opts.typ = "dpop+jwt"
	}
	if opts.iat == 0 {
		opts.iat = time.Now().Unix()
	}
	h, _ := json.Marshal(map[string]string{"alg": opts.alg, "typ": opts.typ})
	p, _ := json.Marshal(map[string]any{
		"iat": opts.iat, "jti": opts.jti, "htm": opts.htm, "htu": opts.htu,
	})
	enc := base64.RawURLEncoding.EncodeToString
	msg := enc(h) + "." + enc(p)
	key := d.priv
	if opts.signer != nil {
		key = opts.signer
	}
	sig := ed25519.Sign(key, []byte(msg))
	return msg + "." + enc(sig)
}

// verifyWith runs Verify against a synthetic request and returns
// (dock_id, http status). Status is 200 when Verify never wrote an error.
func verifyWith(database *sql.DB, dockID, jwt, method, target string) (string, int) {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Authorization", "DPoP "+dockID)
	r.Header.Set("DPoP", jwt)
	w := httptest.NewRecorder()
	got := Verify(database, w, r)
	return got, w.Code
}

const testURL = "http://hub.test/v1/artifacts"

func TestVerifyAcceptsValidProofAndBurnsJTI(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_ok")

	jwt := d.proof(t, proofOpts{jti: "jti-1", htm: "POST", htu: testURL})
	got, code := verifyWith(database, d.dockID, jwt, "POST", testURL)
	if got != d.dockID || code != 200 {
		t.Fatalf("valid proof must pass: got=%q code=%d", got, code)
	}

	// The SAME proof replayed must reject: jti is single-use.
	got, code = verifyWith(database, d.dockID, jwt, "POST", testURL)
	if got != "" || code != 401 {
		t.Fatalf("replayed jti must reject: got=%q code=%d", got, code)
	}
}

func TestVerifyRejectsWrongKeySignature(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_a")
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)

	// Signed by a key that is NOT the dock's registered key.
	jwt := d.proof(t, proofOpts{jti: "jti-forge", htm: "POST", htu: testURL, signer: otherPriv})
	if got, code := verifyWith(database, d.dockID, jwt, "POST", testURL); got != "" || code != 401 {
		t.Fatalf("foreign-key signature must reject: got=%q code=%d", got, code)
	}
}

func TestVerifyRejectsUnknownDock(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_known")

	jwt := d.proof(t, proofOpts{jti: "jti-ghost", htm: "POST", htu: testURL})
	// Valid proof, but presented under a dock_id the hub has never seen —
	// the exact post-database-wipe condition that motivated the attach probe.
	if got, code := verifyWith(database, "dck_ghost", jwt, "POST", testURL); got != "" || code != 401 {
		t.Fatalf("unknown dock must reject: got=%q code=%d", got, code)
	}
}

func TestVerifyRejectsMethodAndURLBindingMismatches(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_bind")

	// htm says POST, request is GET: a captured proof must not authorize a
	// different operation.
	jwt := d.proof(t, proofOpts{jti: "jti-htm", htm: "POST", htu: testURL})
	if got, code := verifyWith(database, d.dockID, jwt, "GET", testURL); got != "" || code != 401 {
		t.Fatalf("htm mismatch must reject: got=%q code=%d", got, code)
	}

	// htu bound to a different endpoint: a proof minted for one URL must
	// not authorize another.
	jwt = d.proof(t, proofOpts{jti: "jti-htu", htm: "POST", htu: "http://hub.test/v1/merkle/checkpoint"})
	if got, code := verifyWith(database, d.dockID, jwt, "POST", testURL); got != "" || code != 401 {
		t.Fatalf("htu mismatch must reject: got=%q code=%d", got, code)
	}
}

func TestVerifyRejectsClockSkew(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_time")

	for name, iat := range map[string]int64{
		"stale":  time.Now().Unix() - 120,
		"future": time.Now().Unix() + 120,
	} {
		jwt := d.proof(t, proofOpts{jti: "jti-" + name, iat: iat, htm: "POST", htu: testURL})
		if got, code := verifyWith(database, d.dockID, jwt, "POST", testURL); got != "" || code != 401 {
			t.Fatalf("%s iat must reject: got=%q code=%d", name, got, code)
		}
	}
}

func TestVerifyRejectsWrongAlgAndMalformedJWT(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_alg")

	// alg confusion: only EdDSA/dpop+jwt is accepted.
	jwt := d.proof(t, proofOpts{alg: "none", jti: "jti-alg", htm: "POST", htu: testURL})
	if got, code := verifyWith(database, d.dockID, jwt, "POST", testURL); got != "" || code != 401 {
		t.Fatalf("alg=none must reject: got=%q code=%d", got, code)
	}

	for name, raw := range map[string]string{
		"two-part":   "aaaa.bbbb",
		"not-base64": "!!.!!.!!",
		"empty":      "",
	} {
		if got, code := verifyWith(database, d.dockID, raw, "POST", testURL); got != "" || code != 401 {
			t.Fatalf("%s JWT must reject: got=%q code=%d", name, got, code)
		}
	}

	// Missing/blank Authorization forms.
	r := httptest.NewRequest("POST", testURL, nil)
	r.Header.Set("DPoP", d.proof(t, proofOpts{jti: "jti-noauth", htm: "POST", htu: testURL}))
	w := httptest.NewRecorder()
	if got := Verify(database, w, r); got != "" || w.Code != 401 {
		t.Fatalf("missing Authorization must reject: got=%q code=%d", got, w.Code)
	}
}

func TestVerifyTamperedPayloadRejects(t *testing.T) {
	database := openTestDB(t)
	d := registerDock(t, database, "dck_tamper")

	jwt := d.proof(t, proofOpts{jti: "jti-t", htm: "POST", htu: testURL})
	// Swap in a fresh payload under the ORIGINAL signature.
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "dpop+jwt"})
	p, _ := json.Marshal(map[string]any{
		"iat": time.Now().Unix(), "jti": "jti-t2", "htm": "POST", "htu": testURL,
	})
	enc := base64.RawURLEncoding.EncodeToString
	// Take the ORIGINAL signature but swap in a fresh payload.
	origSig := jwt[len(jwt)-fmtLen(jwt):]
	tampered := enc(h) + "." + enc(p) + "." + origSig
	if got, code := verifyWith(database, d.dockID, tampered, "POST", testURL); got != "" || code != 401 {
		t.Fatalf("tampered payload with stale signature must reject: got=%q code=%d", got, code)
	}
}

// fmtLen returns the length of the final JWT segment (the signature).
func fmtLen(jwt string) int {
	for i := len(jwt) - 1; i >= 0; i-- {
		if jwt[i] == '.' {
			return len(jwt) - i - 1
		}
	}
	return 0
}
