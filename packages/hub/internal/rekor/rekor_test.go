package rekor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/zerkerlabs/treeship/packages/hub/internal/contentaddress"
)

// treeshipEnvelope signs payload the way the Rust core does: plain Ed25519
// over PAE, payload and signature as unpadded base64url.
func treeshipEnvelope(t *testing.T, payloadType string, payload []byte, keys ...ed25519.PrivateKey) string {
	t.Helper()
	pae := contentaddress.PAE(payloadType, payload)
	sigs := []map[string]string{}
	for i, k := range keys {
		sigs = append(sigs, map[string]string{
			"keyid": "key_" + string(rune('a'+i)),
			"sig":   base64.RawURLEncoding.EncodeToString(ed25519.Sign(k, pae)),
		})
	}
	b, err := json.Marshal(map[string]any{
		"payloadType": payloadType,
		"payload":     base64.RawURLEncoding.EncodeToString(payload),
		"signatures":  sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

type proposed struct {
	Kind string `json:"kind"`
	Spec struct {
		ProposedContent struct {
			Envelope  string   `json:"envelope"`
			Verifiers []string `json:"verifiers"`
		} `json:"proposedContent"`
	} `json:"spec"`
}

// The exact defect behind TS-2026-003: a Treeship signature is unpadded
// base64url, which Rekor's standard-base64 decoder rejects. The entry must
// carry padded standard base64, and the signature must still verify over PAE
// with the key Rekor is given.
func TestBuildEntryUsesStandardBase64AndVerifiesOverPAE(t *testing.T) {
	pub, priv := newKey(t)
	payload := []byte(`{"type":"treeship/action/v1","actor":"agent://x"}`)
	body, err := BuildEntry(treeshipEnvelope(t, "application/vnd.treeship.action.v1+json", payload, priv), pub)
	if err != nil {
		t.Fatal(err)
	}
	var p proposed
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatal(err)
	}
	if p.Kind != "dsse" {
		t.Fatalf("kind = %q, want dsse (hashedrekord cannot verify plain Ed25519)", p.Kind)
	}
	var env struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(p.Spec.ProposedContent.Envelope), &env); err != nil {
		t.Fatal(err)
	}
	gotPayload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		t.Fatalf("payload is not padded standard base64: %v", err)
	}
	if string(gotPayload) != string(payload) {
		t.Fatal("payload bytes changed")
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		t.Fatalf("signature is not padded standard base64: %v", err)
	}
	pemBytes, err := base64.StdEncoding.DecodeString(p.Spec.ProposedContent.Verifiers[0])
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("verifier is not a PEM public key")
	}
	k, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(k.(ed25519.PublicKey), contentaddress.PAE(env.PayloadType, gotPayload), sig) {
		t.Fatal("submitted signature does not verify over PAE with the submitted key")
	}
}

// Rekor requires every signature in a dsse envelope to verify under a
// supplied key, and the hub only knows the ship key. Foreign signatures are
// dropped rather than making the whole entry fail.
func TestBuildEntryKeepsOnlyShipSignatures(t *testing.T) {
	shipPub, shipPriv := newKey(t)
	_, agentPriv := newKey(t)
	body, err := BuildEntry(treeshipEnvelope(t, "t", []byte("x"), agentPriv, shipPriv), shipPub)
	if err != nil {
		t.Fatal(err)
	}
	var p proposed
	_ = json.Unmarshal(body, &p)
	if n := strings.Count(p.Spec.ProposedContent.Envelope, `"sig"`); n != 1 {
		t.Fatalf("kept %d signatures, want 1", n)
	}
}

func TestBuildEntrySkipsArtifactWithoutShipSignature(t *testing.T) {
	shipPub, _ := newKey(t)
	_, agentPriv := newKey(t)
	if _, err := BuildEntry(treeshipEnvelope(t, "t", []byte("x"), agentPriv), shipPub); err == nil {
		t.Fatal("expected a skip reason for an agent-key-only artifact")
	}
}

func fakeEntry(idx int64) map[string]any {
	return map[string]any{
		"body":           "e30=",
		"integratedTime": 1790000000,
		"logID":          "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		"logIndex":       idx,
		"verification":   map[string]any{"signedEntryTimestamp": "MEU="},
	}
}

func TestAnchorReturnsFullEntry(t *testing.T) {
	pub, priv := newKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"24296fb2": fakeEntry(42)})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res := c.Anchor(context.Background(), treeshipEnvelope(t, "t", []byte("x"), priv), pub)
	if res.Status != StatusAnchored || res.LogIndex == nil || *res.LogIndex != 42 {
		t.Fatalf("got %+v", res)
	}
	var e map[string]any
	_ = json.Unmarshal(res.Entry, &e)
	if e["uuid"] != "24296fb2" || e["verification"] == nil {
		t.Fatalf("entry lost fields: %s", res.Entry)
	}
}

func TestAnchorReportsRejectionInsteadOfSwallowingIt(t *testing.T) {
	pub, priv := newKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":400,"message":"illegal base64 data"}`))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res := c.Anchor(context.Background(), treeshipEnvelope(t, "t", []byte("x"), priv), pub)
	if res.Status != StatusFailed || !strings.Contains(res.Reason, "illegal base64") {
		t.Fatalf("got %+v", res)
	}
}

func TestAnchorFollowsConflictToExistingEntry(t *testing.T) {
	pub, priv := newKey(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/log/entries", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/api/v1/log/entries/abc")
		w.WriteHeader(http.StatusConflict)
	})
	mux.HandleFunc("/api/v1/log/entries/abc", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"abc": fakeEntry(7)})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res := c.Anchor(context.Background(), treeshipEnvelope(t, "t", []byte("x"), priv), pub)
	if res.Status != StatusAnchored || *res.LogIndex != 7 {
		t.Fatalf("got %+v", res)
	}
}

func TestAnchorRefusesEntryWithoutProof(t *testing.T) {
	pub, priv := newKey(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e := fakeEntry(1)
		delete(e, "verification")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"u": e})
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if res := c.Anchor(context.Background(), treeshipEnvelope(t, "t", []byte("x"), priv), pub); res.Status != StatusFailed {
		t.Fatalf("an entry with no verification block must not count as anchored: %+v", res)
	}
}

// TestLiveStaging submits a throwaway-key entry to Sigstore's staging Rekor,
// which exists for exactly this. Opt-in: TREESHIP_REKOR_LIVE=1. It proves the
// entry format is accepted by a real Rekor, which the fakes above cannot.
func TestLiveStaging(t *testing.T) {
	if os.Getenv("TREESHIP_REKOR_LIVE") != "1" {
		t.Skip("set TREESHIP_REKOR_LIVE=1 to submit to rekor.sigstage.dev")
	}
	pub, priv := newKey(t)
	payload := []byte(`{"type":"treeship/test/v1","nonce":"` + time.Now().Format(time.RFC3339Nano) + `"}`)
	c := &Client{BaseURL: "https://rekor.sigstage.dev", HTTP: &http.Client{Timeout: 20 * time.Second}}
	res := c.Anchor(context.Background(), treeshipEnvelope(t, "application/vnd.treeship.test+json", payload, priv), pub)
	if res.Status != StatusAnchored {
		t.Fatalf("staging Rekor did not accept the entry: %+v", res)
	}
	if out := os.Getenv("TREESHIP_REKOR_LIVE_OUT"); out != "" {
		fixture, _ := json.MarshalIndent(map[string]any{
			"envelope":   json.RawMessage(treeshipEnvelopeFor(payload, priv)),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"entry":      res.Entry,
		}, "", " ")
		_ = os.WriteFile(out, fixture, 0o644)
	}
	t.Logf("anchored at staging log index %d", *res.LogIndex)
}

func treeshipEnvelopeFor(payload []byte, priv ed25519.PrivateKey) string {
	pt := "application/vnd.treeship.test+json"
	sig := ed25519.Sign(priv, contentaddress.PAE(pt, payload))
	b, _ := json.Marshal(map[string]any{
		"payloadType": pt,
		"payload":     base64.RawURLEncoding.EncodeToString(payload),
		"signatures":  []map[string]string{{"keyid": "key_a", "sig": base64.RawURLEncoding.EncodeToString(sig)}},
	})
	return string(b)
}
