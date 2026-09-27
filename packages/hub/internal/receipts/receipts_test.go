package receipts

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/zerkerlabs/treeship/packages/hub/internal/db"
)

// A dock registered in a throwaway database, with the key that signs its
// DPoP proofs (the same shape dpop_test.go uses).
type testDock struct {
	id   string
	priv ed25519.PrivateKey
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

func registerDock(t *testing.T, database *sql.DB, id string) testDock {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := db.InsertShip(database, id, pub, pub, time.Now().Unix()); err != nil {
		t.Fatalf("insert ship: %v", err)
	}
	return testDock{id: id, priv: priv}
}

// proof signs a DPoP proof bound to method + url with a fresh jti (or the
// one given, to replay it).
func (d testDock) proof(method, url, jti string) string {
	if jti == "" {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		jti = base64.RawURLEncoding.EncodeToString(b)
	}
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "dpop+jwt"})
	p, _ := json.Marshal(map[string]any{"iat": time.Now().Unix(), "jti": jti, "htm": method, "htu": url})
	enc := base64.RawURLEncoding.EncodeToString
	msg := enc(h) + "." + enc(p)
	return msg + "." + enc(ed25519.Sign(d.priv, []byte(msg)))
}

// router wires the receipt routes the way main.go does, HEAD included.
func router(h *Handlers) chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.GetHead)
	r.Put("/v1/receipt/{session_id}", h.PutReceipt)
	r.Get("/v1/receipt/{session_id}", h.GetReceipt)
	r.Delete("/v1/receipt/{session_id}", h.DeleteReceipt)
	return r
}

const host = "http://hub.test"

func do(r chi.Router, method, path string, body []byte, dock *testDock, jti string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, host+path, bytes.NewReader(body))
	if dock != nil {
		req.Header.Set("Authorization", "DPoP "+dock.id)
		req.Header.Set("DPoP", dock.proof(method, host+path, jti))
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func receiptBody(sessionID string) []byte {
	b, _ := json.Marshal(map[string]any{
		"type":         "treeship/session-receipt/v1",
		"session":      map[string]any{"id": sessionID, "name": "s", "status": "closed"},
		"participants": map[string]any{"total_agents": 1},
		"timeline":     []any{},
		"agent_graph":  map[string]any{"nodes": []any{}},
		"secret":       "/Users/someone/private",
	})
	return b
}

func TestOwnerTakesDownAndTheBytesAreGone(t *testing.T) {
	database := openTestDB(t)
	owner := registerDock(t, database, "dock_owner00000000")
	r := router(&Handlers{DB: database})

	if w := do(r, "PUT", "/v1/receipt/ssn_1", receiptBody("ssn_1"), &owner, ""); w.Code != 200 {
		t.Fatalf("put: %d %s", w.Code, w.Body.String())
	}
	if w := do(r, "GET", "/v1/receipt/ssn_1", nil, nil, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "private") {
		t.Fatalf("get before takedown: %d %s", w.Code, w.Body.String())
	}

	w := do(r, "DELETE", "/v1/receipt/ssn_1", []byte(`{"reason":"leaked local paths"}`), &owner, "")
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}

	w = do(r, "GET", "/v1/receipt/ssn_1", nil, nil, "")
	if w.Code != http.StatusGone {
		t.Fatalf("get after takedown: want 410, got %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private") {
		t.Fatalf("the old bytes came back: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "leaked local paths") {
		t.Fatalf("reason missing: %s", w.Body.String())
	}
	if cc := w.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("410 must not be cacheable, got %q", cc)
	}
	// The stored row keeps no body.
	sess, err := db.GetSession(database, "ssn_1")
	if err != nil {
		t.Fatal(err)
	}
	if sess.ReceiptJSON != nil {
		t.Fatalf("receipt body still stored: %q", *sess.ReceiptJSON)
	}
	if sess.TombstonedAt == nil || sess.DockID != owner.id {
		t.Fatalf("tombstone not recorded: %+v", sess)
	}
	// The slot is retired: no second upload, no second takedown.
	if w := do(r, "PUT", "/v1/receipt/ssn_1", receiptBody("ssn_1"), &owner, ""); w.Code != http.StatusGone {
		t.Fatalf("put after takedown: want 410, got %d %s", w.Code, w.Body.String())
	}
	if w := do(r, "DELETE", "/v1/receipt/ssn_1", nil, &owner, ""); w.Code != http.StatusGone {
		t.Fatalf("second delete: want 410, got %d", w.Code)
	}
}

func TestOnlyThePublishingDockCanTakeDown(t *testing.T) {
	database := openTestDB(t)
	owner := registerDock(t, database, "dock_owner00000000")
	other := registerDock(t, database, "dock_other00000000")
	r := router(&Handlers{DB: database})
	if w := do(r, "PUT", "/v1/receipt/ssn_2", receiptBody("ssn_2"), &owner, ""); w.Code != 200 {
		t.Fatalf("put: %d", w.Code)
	}
	if w := do(r, "DELETE", "/v1/receipt/ssn_2", nil, &other, ""); w.Code != http.StatusForbidden {
		t.Fatalf("other dock: want 403, got %d %s", w.Code, w.Body.String())
	}
	if w := do(r, "GET", "/v1/receipt/ssn_2", nil, nil, ""); w.Code != 200 {
		t.Fatalf("receipt must still be served after a refused takedown: %d", w.Code)
	}
	if w := do(r, "DELETE", "/v1/receipt/ssn_2", nil, nil, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("no auth: want 401, got %d", w.Code)
	}
	if w := do(r, "DELETE", "/v1/receipt/ssn_missing", nil, &owner, ""); w.Code != http.StatusNotFound {
		t.Fatalf("missing: want 404, got %d", w.Code)
	}
}

func TestAReplayedProofIsRefused(t *testing.T) {
	database := openTestDB(t)
	owner := registerDock(t, database, "dock_owner00000000")
	r := router(&Handlers{DB: database})
	if w := do(r, "PUT", "/v1/receipt/ssn_3", receiptBody("ssn_3"), &owner, ""); w.Code != 200 {
		t.Fatalf("put: %d", w.Code)
	}
	// A proof captured from a first request (same jti) cannot drive a second.
	jti := "captured-jti-000001"
	if w := do(r, "DELETE", "/v1/receipt/ssn_3", nil, &owner, jti); w.Code != 200 {
		t.Fatalf("first use: %d %s", w.Code, w.Body.String())
	}
	w := do(r, "DELETE", "/v1/receipt/ssn_3", nil, &owner, jti)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed proof: want 401, got %d %s", w.Code, w.Body.String())
	}
	// A proof bound to PUT does not authorize DELETE either.
	req := httptest.NewRequest("DELETE", host+"/v1/receipt/ssn_3", nil)
	req.Header.Set("Authorization", "DPoP "+owner.id)
	req.Header.Set("DPoP", owner.proof("PUT", host+"/v1/receipt/ssn_3", ""))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("method-mismatched proof: want 401, got %d", rec.Code)
	}
}

func TestHeadIsServedOnGetRoutes(t *testing.T) {
	database := openTestDB(t)
	owner := registerDock(t, database, "dock_owner00000000")
	r := router(&Handlers{DB: database})
	if w := do(r, "PUT", "/v1/receipt/ssn_4", receiptBody("ssn_4"), &owner, ""); w.Code != 200 {
		t.Fatalf("put: %d", w.Code)
	}
	// Through a real server: net/http drops the body of a HEAD response,
	// which the recorder alone does not, and the router used to answer 405.
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Head(srv.URL + "/v1/receipt/ssn_4")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("HEAD: want 200, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") == "" {
		t.Fatalf("HEAD carried no headers of the GET: %v", resp.Header)
	}
	buf := make([]byte, 16)
	if n, _ := resp.Body.Read(buf); n != 0 {
		t.Fatalf("HEAD carried a body")
	}
	// And a missing receipt is a 404 on HEAD too, not a 405.
	resp2, err := http.Head(srv.URL + "/v1/receipt/ssn_missing")
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("HEAD missing: want 404, got %d", resp2.StatusCode)
	}
}
