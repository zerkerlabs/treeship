// Package contentaddress re-derives an artifact's identity from the bytes it
// carries, rather than believing what the uploader said about them.
//
// # Why this exists
//
// The Hub used to store `artifact_id`, `payload_type` and `digest` exactly as
// the caller supplied them, alongside the envelope, and never checked that the
// three agreed. Combined with `ON CONFLICT(artifact_id) DO NOTHING`, that made
// the publishing namespace writable by anyone with a dock:
//
//  1. Pick a legitimate-looking (or known) artifact ID.
//  2. Upload unrelated bytes under it.
//  3. Win the first-write race.
//  4. The real upload is silently ignored -- and still gets a 200.
//
// Local verification catches the mismatch, so this was never a forged pass.
// But `art_` is supposed to *mean* something: an ID is a claim about content,
// and a store that lets the two diverge has stopped being content-addressed
// while still looking like it. Squatting and targeted denial follow.
//
// # The derivation
//
// This mirrors packages/core/src/attestation/{pae,id}.rs exactly, and the two
// are pinned together by shared vectors in tests/vectors/artifact-ids.json:
//
//	PAE    = "DSSEv1 " + len(payloadType) + " " + payloadType + " " +
//	         len(payload) + " " + payload      (payload = RAW decoded bytes)
//	art_id = "art_" + hex(sha256(PAE)[:16])
//	digest = "sha256:" + hex(sha256(PAE))
//
// The payload inside a DSSE envelope is base64url without padding
// (`URL_SAFE_NO_PAD` in Rust, `base64.RawURLEncoding` here). PAE covers the
// decoded bytes, not the encoded string -- getting that wrong yields a
// plausible-looking ID that never matches a real one.
package contentaddress

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Envelope is the subset of a DSSE envelope needed to derive identity.
type Envelope struct {
	PayloadType string `json:"payloadType"`
	Payload     string `json:"payload"`
}

// Derived is what the bytes themselves say the artifact is.
type Derived struct {
	ArtifactID  string
	Digest      string
	PayloadType string
}

var (
	// ErrMalformed means the envelope could not be parsed or decoded, so no
	// derivation is possible. Distinct from a mismatch: nothing was compared.
	ErrMalformed = errors.New("envelope is malformed")
	// ErrMismatch means the submitted fields disagree with the bytes.
	ErrMismatch = errors.New("submitted fields do not match the envelope")
)

// PAE builds the DSSE Pre-Authentication Encoding over raw payload bytes.
func PAE(payloadType string, payload []byte) []byte {
	var b strings.Builder
	b.Grow(7 + 20 + len(payloadType) + 20 + len(payload))
	b.WriteString("DSSEv1 ")
	fmt.Fprintf(&b, "%d", len(payloadType))
	b.WriteByte(' ')
	b.WriteString(payloadType)
	b.WriteByte(' ')
	fmt.Fprintf(&b, "%d", len(payload))
	b.WriteByte(' ')
	return append([]byte(b.String()), payload...)
}

// Derive computes the artifact identity implied by an envelope's own bytes.
func Derive(envelopeJSON string) (*Derived, error) {
	var env Envelope
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return nil, fmt.Errorf("%w: not valid JSON: %v", ErrMalformed, err)
	}
	if env.PayloadType == "" {
		return nil, fmt.Errorf("%w: envelope has no payloadType", ErrMalformed)
	}
	if env.Payload == "" {
		return nil, fmt.Errorf("%w: envelope has no payload", ErrMalformed)
	}

	// Accept padded input too: some clients emit standard base64url with
	// padding, and rejecting a well-formed envelope over that would be a
	// compatibility break with no security benefit. The decoded bytes are
	// what matters, and they are identical either way.
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(env.Payload, "="))
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrMalformed, err)
	}

	sum := sha256.Sum256(PAE(env.PayloadType, payload))
	return &Derived{
		ArtifactID:  "art_" + hex.EncodeToString(sum[:16]),
		Digest:      "sha256:" + hex.EncodeToString(sum[:]),
		PayloadType: env.PayloadType,
	}, nil
}

// Check verifies that what the caller claimed matches what the bytes say.
//
// Every mismatch is reported together rather than short-circuiting on the
// first. A caller that got two fields wrong should learn both at once, and a
// caller probing the namespace should not be able to use which error came
// back as an oracle for how far their forgery got.
func Check(envelopeJSON, claimedID, claimedDigest, claimedPayloadType string) (*Derived, error) {
	d, err := Derive(envelopeJSON)
	if err != nil {
		return nil, err
	}

	var problems []string
	if claimedID != d.ArtifactID {
		problems = append(problems,
			fmt.Sprintf("artifact_id %q but envelope derives %q", claimedID, d.ArtifactID))
	}
	if claimedDigest != d.Digest {
		problems = append(problems,
			fmt.Sprintf("digest %q but envelope derives %q", claimedDigest, d.Digest))
	}
	if claimedPayloadType != d.PayloadType {
		problems = append(problems,
			fmt.Sprintf("payload_type %q but envelope declares %q",
				claimedPayloadType, d.PayloadType))
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrMismatch, strings.Join(problems, "; "))
	}
	return d, nil
}

// SameBytes reports whether two stored envelopes are byte-identical.
//
// Used on an ID collision to tell a retry from a takeover. Compared as raw
// strings deliberately: two envelopes that differ only in JSON formatting
// still carry different bytes, and "the bytes we already stored" is what a
// puller will receive. Normalising here would let a re-push change what is
// served while reporting the two as the same.
func SameBytes(a, b string) bool {
	return a == b
}

// Indexable is the metadata the hub indexes on, derived from the envelope's
// own signed bytes.
//
// Derived, never accepted. An index built from caller-supplied fields lets an
// uploader choose how their artifact is found -- and a resolver filtering on
// it is filtering on the uploader's claim about itself, not on the content.
// That is audit item 11, and it is the same reason `Check` above re-derives
// the artifact id rather than trusting the one submitted.
//
// Both fields are optional. A statement without a `kind`, or one that is not a
// receipt, indexes as NULL rather than as a guess, and queries must treat NULL
// as "not derived" rather than "does not match".
type Indexable struct {
	Kind  *string
	Actor *string
}

// DeriveIndexable extracts the indexable fields from an envelope.
//
// Never errors: an envelope that will not decode simply has nothing to index,
// and refusing the whole ingestion over an unindexable artifact would reject
// content the store is otherwise happy to hold.
func DeriveIndexable(envelopeJSON string) Indexable {
	var env Envelope
	if json.Unmarshal([]byte(envelopeJSON), &env) != nil {
		return Indexable{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(env.Payload, "="))
	if err != nil {
		return Indexable{}
	}

	// Receipts carry `kind` plus a payload that may name an actor; action
	// statements name the actor at the top level. Read both shapes rather than
	// assuming one, since the store holds both.
	var stmt struct {
		Kind    string          `json:"kind"`
		Actor   string          `json:"actor"`
		Payload json.RawMessage `json:"payload"`
	}
	if json.Unmarshal(payload, &stmt) != nil {
		return Indexable{}
	}

	out := Indexable{}
	if stmt.Kind != "" {
		k := stmt.Kind
		out.Kind = &k
	}
	actor := stmt.Actor
	if actor == "" && len(stmt.Payload) > 0 {
		var inner struct {
			Actor string `json:"actor"`
			Agent string `json:"agent"`
		}
		if json.Unmarshal(stmt.Payload, &inner) == nil {
			// `agent` is the agent_card/cert spelling of the same idea. Folding
			// them into one column is what lets a single index answer "this
			// agent's records" across receipt kinds.
			if inner.Actor != "" {
				actor = inner.Actor
			} else if inner.Agent != "" {
				actor = inner.Agent
			}
		}
	}
	if actor != "" {
		out.Actor = &actor
	}
	return out
}
