package dpop_test

// The test that matters here is the round trip: proofs minted by this package
// are handed to the REAL server verifier in internal/dpop, against a real
// database with a real registered dock.
//
// A client-side signer tested only against its own idea of correctness is
// worthless -- the failure mode it exists to prevent is exactly a client and
// server that disagree about canonical bytes, which surfaces in production as
// an opaque 401. So these tests assert agreement with the thing that will
// actually judge the proof.

import (
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/treeship/hub/internal/db"
	serverdpop "github.com/treeship/hub/internal/dpop"
	"github.com/treeship/hub/pkg/dpop"
)

// registerDock mints a keypair, registers it as a ship, and returns a client
// Signer built from the same seed the server will verify against.
func registerDock(t *testing.T, database *sql.DB, dockID string) *dpop.Signer {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if err := db.InsertShip(database, dockID, pub, pub, time.Now().Unix()); err != nil {
		t.Fatalf("insert ship: %v", err)
	}
	signer, err := dpop.NewSigner(dockID, hex.EncodeToString(priv.Seed()))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	return signer
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

// verify runs the real server verifier over a signed request and reports the
// dock id it resolved ("" on rejection).
func verify(t *testing.T, database *sql.DB, req *http.Request) string {
	t.Helper()
	return serverdpop.Verify(database, httptest.NewRecorder(), req)
}

// The headline: a proof this package mints is accepted by the server.
func TestSignedRequestVerifiesServerSide(t *testing.T) {
	database := openTestDB(t)
	signer := registerDock(t, database, "dck_roundtrip")

	req := httptest.NewRequest("PUT", "https://api.treeship.dev/v1/receipt/ssn_abc", nil)
	if err := signer.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}

	if got := verify(t, database, req); got != "dck_roundtrip" {
		t.Fatalf("server rejected a proof from our own signer (dock=%q)", got)
	}
}

// jti is single-use. Replaying a proof must fail even though it is otherwise
// valid and unexpired -- this is the property that makes a captured proof
// worthless.
func TestReplayedProofIsRejected(t *testing.T) {
	database := openTestDB(t)
	signer := registerDock(t, database, "dck_replay")

	url := "https://api.treeship.dev/v1/receipt/ssn_abc"
	first := httptest.NewRequest("PUT", url, nil)
	if err := signer.Sign(first); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if verify(t, database, first) == "" {
		t.Fatal("first request should verify")
	}

	// Same proof bytes, second request.
	replay := httptest.NewRequest("PUT", url, nil)
	replay.Header = first.Header.Clone()
	if got := verify(t, database, replay); got != "" {
		t.Fatal("a replayed proof was accepted; jti is not being burned")
	}
}

// Every proof must be independently usable. A signer that reused jti or a
// cached proof would break any caller signing concurrently -- a room service
// pushing several receipts at once is the motivating case.
func TestConsecutiveProofsAreIndependent(t *testing.T) {
	database := openTestDB(t)
	signer := registerDock(t, database, "dck_concurrent")

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest("PUT", "https://api.treeship.dev/v1/receipt/ssn_abc", nil)
		if err := signer.Sign(req); err != nil {
			t.Fatalf("sign %d: %v", i, err)
		}
		if verify(t, database, req) == "" {
			t.Fatalf("proof %d rejected; proofs are not independent", i)
		}
	}
}

// htm/htu bind a proof to one method and one URL. A proof lifted from a GET
// must not authorize a PUT, and one signed for a read path must not authorize
// a write path on the same host.
func TestProofIsBoundToMethodAndURL(t *testing.T) {
	database := openTestDB(t)
	signer := registerDock(t, database, "dck_binding")

	t.Run("method", func(t *testing.T) {
		proof, err := signer.Proof("GET", "https://api.treeship.dev/v1/receipt/ssn_abc")
		if err != nil {
			t.Fatalf("proof: %v", err)
		}
		req := httptest.NewRequest("PUT", "https://api.treeship.dev/v1/receipt/ssn_abc", nil)
		req.Header.Set("Authorization", "DPoP "+signer.HubID())
		req.Header.Set("DPoP", proof)
		if verify(t, database, req) != "" {
			t.Fatal("a GET proof authorized a PUT")
		}
	})

	t.Run("url", func(t *testing.T) {
		proof, err := signer.Proof("PUT", "https://api.treeship.dev/v1/receipt/ssn_OTHER")
		if err != nil {
			t.Fatalf("proof: %v", err)
		}
		req := httptest.NewRequest("PUT", "https://api.treeship.dev/v1/receipt/ssn_abc", nil)
		req.Header.Set("Authorization", "DPoP "+signer.HubID())
		req.Header.Set("DPoP", proof)
		if verify(t, database, req) != "" {
			t.Fatal("a proof for one session authorized another")
		}
	})
}

// A signer holding the wrong key must be rejected. Guards against the server
// resolving the dock by id and then not actually checking the signature.
func TestUnregisteredKeyIsRejected(t *testing.T) {
	database := openTestDB(t)
	registerDock(t, database, "dck_real")

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	impostor, err := dpop.NewSigner("dck_real", hex.EncodeToString(priv.Seed()))
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	req := httptest.NewRequest("PUT", "https://api.treeship.dev/v1/receipt/ssn_abc", nil)
	if err := impostor.Sign(req); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if verify(t, database, req) != "" {
		t.Fatal("a proof signed with the wrong key was accepted")
	}
}

// Constructor input validation: a bad seed must fail loudly at construction,
// not produce a signer that mints proofs nothing will accept.
func TestNewSignerRejectsBadInput(t *testing.T) {
	valid := hex.EncodeToString(make([]byte, ed25519.SeedSize))
	cases := []struct{ name, hubID, secret string }{
		{"empty hub id", "", valid},
		{"not hex", "dck_x", "nothex!!"},
		{"wrong length", "dck_x", hex.EncodeToString(make([]byte, 16))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := dpop.NewSigner(tc.hubID, tc.secret); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
