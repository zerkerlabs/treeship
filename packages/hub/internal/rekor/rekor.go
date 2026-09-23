// Package rekor anchors pushed artifacts in the public Rekor transparency log.
//
// # What was wrong before (TS-2026-003)
//
// The first version submitted a `hashedrekord` entry: the SHA-256 of the
// artifact's PAE bytes plus the envelope's first signature. That could never
// succeed, for two independent reasons:
//
//  1. Treeship envelopes carry signatures as unpadded base64url. Rekor
//     decodes `signature.content` as padded standard base64, so every
//     submission failed with "illegal base64 data".
//  2. Even with the encoding fixed, `hashedrekord` verifies Ed25519 only in
//     its pre-hashed variant (Ed25519ph). Treeship signs plain Ed25519 over the
//     PAE bytes, which cannot be checked against a digest alone.
//
// The failure was logged and swallowed, the push still succeeded, and the CLI
// printed "rekor: pending". No artifact was ever anchored.
//
// # What this does now
//
// It submits a `dsse` entry. Rekor's dsse type verifies each signature over
// the PAE bytes with the supplied public keys, which is exactly how Treeship
// signs. Only signatures made by the dock's registered ship key are submitted
// (Rekor requires every signature in the envelope to verify, and the hub only
// knows that one key); an artifact with no such signature is reported as
// skipped rather than silently dropped.
//
// The full Rekor response is returned -- entry body, integrated time, signed
// entry timestamp, inclusion proof and signed checkpoint -- so the CLI can
// store it and a verifier can check it offline against a pinned Rekor key.
// Returning only the log index, as before, left nothing to verify.
package rekor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/zerkerlabs/treeship/packages/hub/internal/contentaddress"
)

// DefaultURL is the public-good Rekor v1 log.
const DefaultURL = "https://rekor.sigstore.dev"

// Status values, stored and returned verbatim.
const (
	StatusAnchored = "anchored"
	StatusFailed   = "failed"
	StatusSkipped  = "skipped"
)

// Result is the outcome of one anchoring attempt. It is never nil and never
// ambiguous: a missing anchor always says why.
type Result struct {
	Status string `json:"status"`
	// Reason is set for failed and skipped results.
	Reason string `json:"reason,omitempty"`
	// LogIndex is the global Rekor log index, set when anchored.
	LogIndex *int64 `json:"log_index,omitempty"`
	// Entry is the Rekor log entry as Rekor returned it, with its UUID added
	// under "uuid". Set when anchored. This is the proof the CLI staples.
	Entry json.RawMessage `json:"entry,omitempty"`
}

// Client talks to one Rekor instance.
type Client struct {
	BaseURL string
	HTTP    *http.Client
}

// NewDefault returns a client for the public-good log with bounded timeouts.
//
// AUD-23: the default http.Post has NO timeout. A slow or hung Rekor (outage,
// or an on-path attacker holding the socket) blocked artifacts.Push
// indefinitely, pinning a Throttle(100) slot per call. Every round-trip is
// bounded and every response body is size-limited.
func NewDefault() *Client {
	return &Client{BaseURL: DefaultURL, HTTP: &http.Client{Timeout: 10 * time.Second}}
}

type inEnvelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
	Signatures  []struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"signatures"`
}

type outSig struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

type outEnvelope struct {
	PayloadType string   `json:"payloadType"`
	Payload     string   `json:"payload"`
	Signatures  []outSig `json:"signatures"`
}

// decodeB64 accepts base64url or standard base64, padded or not. Treeship
// writes unpadded base64url; tolerating the rest costs nothing because the
// decoded bytes are what gets verified.
func decodeB64(s string) ([]byte, error) {
	t := strings.TrimRight(s, "=")
	if b, err := base64.RawURLEncoding.DecodeString(t); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(t)
}

// BuildEntry turns a Treeship envelope into the Rekor dsse proposed-entry
// request body. It keeps only signatures that verify under shipPub, and
// re-encodes payload and signatures as padded standard base64, which is what
// the DSSE spec and Rekor expect.
//
// Returned errors are skip reasons: nothing was sent.
func BuildEntry(envelopeJSON string, shipPub ed25519.PublicKey) ([]byte, error) {
	if len(shipPub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dock has no valid Ed25519 ship key registered")
	}
	var env inEnvelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return nil, fmt.Errorf("envelope is not valid JSON: %v", err)
	}
	payload, err := decodeB64(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("envelope payload is not base64: %v", err)
	}
	pae := contentaddress.PAE(env.PayloadType, payload)

	var kept []outSig
	for _, s := range env.Signatures {
		sig, err := decodeB64(s.Sig)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(shipPub, pae, sig) {
			kept = append(kept, outSig{KeyID: s.KeyID, Sig: base64.StdEncoding.EncodeToString(sig)})
		}
	}
	if len(kept) == 0 {
		return nil, fmt.Errorf("no signature on this artifact was made by the dock's registered ship key (agent-key-only artifacts are not anchored per artifact)")
	}

	outEnv, err := json.Marshal(outEnvelope{
		PayloadType: env.PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures:  kept,
	})
	if err != nil {
		return nil, err
	}

	spki, err := x509.MarshalPKIXPublicKey(shipPub)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})

	return json.Marshal(map[string]any{
		"apiVersion": "0.0.1",
		"kind":       "dsse",
		"spec": map[string]any{
			"proposedContent": map[string]any{
				"envelope":  string(outEnv),
				"verifiers": []string{base64.StdEncoding.EncodeToString(pemKey)},
			},
		},
	})
}

// Anchor submits the envelope to Rekor and returns the full log entry.
func (c *Client) Anchor(ctx context.Context, envelopeJSON string, shipPub ed25519.PublicKey) Result {
	body, err := BuildEntry(envelopeJSON, shipPub)
	if err != nil {
		return Result{Status: StatusSkipped, Reason: err.Error()}
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/v1/log/entries", bytes.NewReader(body))
	if err != nil {
		return failed("build request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return failed("rekor unreachable: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return failed("read rekor response: %v", err)
	}

	switch {
	case resp.StatusCode == http.StatusConflict:
		// Already in the log (a re-push of bytes someone anchored before).
		// Rekor points at the existing entry; fetch it so the caller still
		// gets a proof instead of a bare "exists".
		loc := resp.Header.Get("Location")
		if loc == "" {
			return failed("rekor reports the entry exists but gave no location")
		}
		return c.fetch(ctx, loc)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return failed("rekor rejected the entry (%d): %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	return parseEntries(respBody)
}

func (c *Client) fetch(ctx context.Context, loc string) Result {
	url := loc
	if strings.HasPrefix(loc, "/") {
		url = c.BaseURL + loc
	}
	if !strings.HasPrefix(url, c.BaseURL+"/") {
		return failed("rekor pointed at an unexpected location %q", loc)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return failed("build request: %v", err)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return failed("rekor unreachable: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return failed("read rekor response: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return failed("fetch existing rekor entry (%d): %s", resp.StatusCode, truncate(string(respBody), 300))
	}
	return parseEntries(respBody)
}

// parseEntries reads Rekor's `{uuid: entry}` response. The hub does not
// verify the proof itself -- verification belongs to whoever relies on it,
// offline, against their own pinned Rekor key -- but it does refuse to call
// something anchored unless the parts a verifier needs are present.
func parseEntries(respBody []byte) Result {
	var m map[string]map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &m); err != nil {
		return failed("rekor response is not an entry map: %v", err)
	}
	if len(m) != 1 {
		return failed("rekor returned %d entries, expected 1", len(m))
	}
	for uuid, entry := range m {
		for _, k := range []string{"body", "integratedTime", "logID", "logIndex", "verification"} {
			if _, ok := entry[k]; !ok {
				return failed("rekor entry is missing %q", k)
			}
		}
		var idx int64
		if err := json.Unmarshal(entry["logIndex"], &idx); err != nil {
			return failed("rekor logIndex is not an integer: %v", err)
		}
		u, _ := json.Marshal(uuid)
		entry["uuid"] = u
		raw, err := json.Marshal(entry)
		if err != nil {
			return failed("re-encode rekor entry: %v", err)
		}
		return Result{Status: StatusAnchored, LogIndex: &idx, Entry: raw}
	}
	return failed("unreachable")
}

func failed(format string, args ...any) Result {
	r := Result{Status: StatusFailed, Reason: fmt.Sprintf(format, args...)}
	log.Printf("rekor: %s", r.Reason)
	return r
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
