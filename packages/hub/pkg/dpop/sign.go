// Package dpop creates DPoP proofs for authenticating to a Treeship Hub.
//
// This is the CLIENT half. `internal/dpop` is the server half: it consumes a
// proof off an inbound request and answers "is this caller who they say."
// Nothing in Go could previously *create* one -- proof signing existed only in
// the Rust CLI (`packages/cli/src/commands/hub.rs`), so a Go service that
// wanted to push a receipt had no path to the API at all.
//
// The two halves are deliberately in the same repo and tested against each
// other (see sign_test.go): a client and server that disagree about the
// canonical bytes fail at runtime with a 401 and no useful signal about why.
//
// # Usage
//
//	signer, err := dpop.NewSigner(hubID, secretHex)
//	req, _ := http.NewRequest("PUT", url, body)
//	if err := signer.Sign(req); err != nil { ... }
//	resp, _ := http.DefaultClient.Do(req)
//
// # What a proof binds
//
// A proof is a JWS over `{iat, jti, htm, htu}` signed with the dock's Ed25519
// secret. `htm`/`htu` bind it to one method and one URL, so a proof captured
// from a GET cannot be replayed against a PUT, or against a different path on
// the same host. `jti` is single-use server-side and `iat` must be within 60
// seconds, so a captured proof is useless almost immediately and useless
// entirely once redeemed.
//
// Sign one proof per request. Reusing a proof across two requests fails on the
// second: the server has already burned the jti.
package dpop

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// MaxClockSkew mirrors the server's tolerance (internal/dpop.maxClockSkew).
// Exported so callers can reason about how stale a pre-signed proof may be.
const MaxClockSkew = 60 * time.Second

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// payload mirrors the server's claim struct exactly. Field names and JSON tags
// must not drift: the server unmarshals into its own copy, and an extra or
// renamed claim silently becomes an unauthenticated request.
type payload struct {
	IAT int64  `json:"iat"`
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
}

// Signer produces DPoP proofs for one dock.
//
// Safe for concurrent use: every call derives fresh `iat` and `jti` and holds
// no mutable state. That matters for a room service signing on behalf of many
// actions at once -- a shared counter or cached proof would collide on jti and
// the second request through would 401.
type Signer struct {
	hubID string
	key   ed25519.PrivateKey
}

// NewSigner builds a Signer from a dock id and its 32-byte Ed25519 seed,
// hex-encoded -- the same `hub_secret_key` the CLI stores in config after
// `treeship hub attach`.
func NewSigner(hubID, secretHex string) (*Signer, error) {
	if hubID == "" {
		return nil, fmt.Errorf("dpop: hub id is required")
	}
	seed, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("dpop: secret key is not valid hex: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("dpop: secret key must be %d bytes, got %d",
			ed25519.SeedSize, len(seed))
	}
	return &Signer{hubID: hubID, key: ed25519.NewKeyFromSeed(seed)}, nil
}

// HubID is the dock id this signer authenticates as.
func (s *Signer) HubID() string { return s.hubID }

// Proof mints a proof bound to one method and URL.
//
// `url` must be exactly the URL the request will be sent to, including scheme
// and host: the server compares `htu` against the URL it received, so a proof
// signed for a redirect target or a path-only URL is rejected.
func (s *Signer) Proof(method, url string) (string, error) {
	if method == "" || url == "" {
		return "", fmt.Errorf("dpop: method and url are required")
	}

	h, err := json.Marshal(header{Alg: "EdDSA", Typ: "dpop+jwt"})
	if err != nil {
		return "", fmt.Errorf("dpop: encode header: %w", err)
	}

	// crypto/rand, not math/rand. jti is a replay guard: a predictable value
	// lets an observer pre-burn the id a client is about to use.
	var jti [16]byte
	if _, err := rand.Read(jti[:]); err != nil {
		return "", fmt.Errorf("dpop: generate jti: %w", err)
	}

	p, err := json.Marshal(payload{
		IAT: time.Now().Unix(),
		JTI: hex.EncodeToString(jti[:]),
		HTM: method,
		HTU: url,
	})
	if err != nil {
		return "", fmt.Errorf("dpop: encode payload: %w", err)
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	sig := ed25519.Sign(s.key, []byte(signingInput))
	return signingInput + "." + enc.EncodeToString(sig), nil
}

// Sign attaches the Authorization and DPoP headers to req, minting a proof
// bound to req's own method and URL.
//
// Prefer this over calling Proof directly: deriving method and URL from the
// request itself removes the failure where a proof is signed for one endpoint
// and sent to another, which surfaces only as an opaque 401.
func (s *Signer) Sign(req *http.Request) error {
	if req == nil || req.URL == nil {
		return fmt.Errorf("dpop: request and url are required")
	}
	proof, err := s.Proof(req.Method, req.URL.String())
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "DPoP "+s.hubID)
	req.Header.Set("DPoP", proof)
	return nil
}
