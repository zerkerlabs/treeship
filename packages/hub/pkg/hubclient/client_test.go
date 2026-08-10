package hubclient_test

// Tests run against an httptest server that applies the REAL server-side DPoP
// verifier over a real database. A client tested against a stub that accepts
// anything proves only that the stub is permissive.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
	serverdpop "github.com/treeship/hub/internal/dpop"
	"github.com/treeship/hub/pkg/hubclient"
)

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

// newHub spins up a server that gates writes behind the real DPoP verifier and
// returns it alongside a Client holding the matching key.
func newHub(t *testing.T) (*httptest.Server, *hubclient.Client, *[]string) {
	t.Helper()
	database := openTestDB(t)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	const dockID = "dck_test"
	if err := db.InsertShip(database, dockID, pub, pub, time.Now().Unix()); err != nil {
		t.Fatalf("insert ship: %v", err)
	}

	var authedAs []string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/receipt/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			dock := serverdpop.Verify(database, w, r)
			if dock == "" {
				return // Verify already wrote the 401
			}
			authedAs = append(authedAs, dock)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"url": "https://treeship.dev/receipt/ssn_abc",
			})
			return
		}
		_, _ = w.Write([]byte(`{"type":"treeship/session-receipt/v1"}`))
	})
	mux.HandleFunc("/v1/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"artifact_id":"art_x","envelope_json":"{}"}`))
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, err := hubclient.New(hubclient.Config{
		HubID:     dockID,
		SecretHex: hex.EncodeToString(priv.Seed()),
		Endpoint:  srv.URL,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return srv, c, &authedAs
}

// The headline: a receipt PUT from this client authenticates end to end.
func TestPutReceiptAuthenticates(t *testing.T) {
	_, c, authedAs := newHub(t)

	url, err := c.PutReceipt(context.Background(), "ssn_abc",
		[]byte(`{"type":"treeship/session-receipt/v1","session":{"id":"ssn_abc"}}`))
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if url == "" {
		t.Fatal("expected a receipt url")
	}
	if len(*authedAs) != 1 || (*authedAs)[0] != "dck_test" {
		t.Fatalf("server did not authenticate the caller: %v", *authedAs)
	}
}

// Each PUT must mint a fresh proof. If the client cached one, the second call
// would 401 on a burned jti -- the bug a room service pushing several receipts
// would hit immediately.
func TestConsecutivePutsEachAuthenticate(t *testing.T) {
	_, c, authedAs := newHub(t)

	for i := 0; i < 3; i++ {
		if _, err := c.PutReceipt(context.Background(), "ssn_abc",
			[]byte(`{"session":{"id":"ssn_abc"}}`)); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if len(*authedAs) != 3 {
		t.Fatalf("expected 3 authenticated puts, got %d -- proofs are being reused", len(*authedAs))
	}
}

// The server rejects a session_id that disagrees with session.id. Catching it
// client-side turns a post-upload 400 into an immediate, specific error.
func TestSessionIDMismatchFailsBeforeUpload(t *testing.T) {
	_, c, authedAs := newHub(t)

	_, err := c.PutReceipt(context.Background(), "ssn_abc",
		[]byte(`{"session":{"id":"ssn_DIFFERENT"}}`))
	if err == nil {
		t.Fatal("expected a mismatch error")
	}
	if len(*authedAs) != 0 {
		t.Fatal("request was sent despite a detectable mismatch")
	}
}

// Public reads are unsigned: signing them would burn a jti per read, and jti
// is single-use.
func TestPublicReadsAreUnsigned(t *testing.T) {
	var sawAuth bool
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/artifacts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") != "" || r.Header.Get("Authorization") != "" {
			sawAuth = true
		}
		_, _ = w.Write([]byte(`{"artifact_id":"art_x"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := hubclient.New(hubclient.Config{
		HubID:     "dck_x",
		SecretHex: hex.EncodeToString(make([]byte, ed25519.SeedSize)),
		Endpoint:  srv.URL,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if _, err := c.GetArtifact(context.Background(), "art_x"); err != nil {
		t.Fatalf("get artifact: %v", err)
	}
	if sawAuth {
		t.Fatal("a public read was signed; that burns a jti for nothing")
	}
}

// A non-2xx must surface as a typed error carrying the server's own message,
// not a generic failure the caller has to guess at.
func TestAPIErrorCarriesStatusAndMessage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/receipt/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unsupported receipt type: nope"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := hubclient.New(hubclient.Config{
		HubID:     "dck_x",
		SecretHex: hex.EncodeToString(make([]byte, ed25519.SeedSize)),
		Endpoint:  srv.URL,
	})
	_, err := c.PutReceipt(context.Background(), "ssn_abc", []byte(`{"session":{"id":"ssn_abc"}}`))
	apiErr, ok := err.(*hubclient.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != 400 || apiErr.Message != "unsupported receipt type: nope" {
		t.Fatalf("error lost detail: %+v", apiErr)
	}
}

// Fail fast on a bad key: a service that starts healthy and cannot
// authenticate is harder to diagnose than one that refuses to start.
func TestNewRejectsBadKey(t *testing.T) {
	if _, err := hubclient.New(hubclient.Config{HubID: "dck_x", SecretHex: "nothex"}); err == nil {
		t.Fatal("expected an error for a malformed key")
	}
}

// Receipts are write-once. A second PUT with different content returns 409,
// and the client must surface that rather than let a caller treat a failed
// publish as cosmetic.
//
// This test exists because spec 0012 described the endpoint as a
// "whole-document overwrite" whose races silently lose a write. The DB layer
// is `InsertSessionWriteOnce`: the race fails loudly instead. Pinning the real
// behavior so the wrong description cannot quietly become true.
func TestWriteOnceConflictIsSurfaced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/receipt/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"receipt already uploaded for this session; receipts are write-once"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, _ := hubclient.New(hubclient.Config{
		HubID:     "dck_x",
		SecretHex: hex.EncodeToString(make([]byte, ed25519.SeedSize)),
		Endpoint:  srv.URL,
	})
	_, err := c.PutReceipt(context.Background(), "ssn_abc", []byte(`{"session":{"id":"ssn_abc"}}`))

	apiErr, ok := err.(*hubclient.APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d", apiErr.StatusCode)
	}
	if !strings.Contains(apiErr.Message, "write-once") {
		t.Fatalf("error should explain write-once semantics, got %q", apiErr.Message)
	}
}
