package contentaddress

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type vectorFile struct {
	Vectors []struct {
		Name        string `json:"name"`
		PayloadType string `json:"payload_type"`
		PayloadB64  string `json:"payload_b64"`
		ArtifactID  string `json:"artifact_id"`
		Digest      string `json:"digest"`
	} `json:"vectors"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "tests", "vectors", "artifact-ids.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read shared vectors at %s: %v", path, err)
	}
	var vf vectorFile
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("parse shared vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("vector file has no vectors; this test would pass vacuously")
	}
	return vf
}

func envelopeFor(payloadType, payloadB64 string) string {
	e, _ := json.Marshal(map[string]string{
		"payloadType": payloadType,
		"payload":     payloadB64,
	})
	return string(e)
}

// The Rust implementation produced these. If Go and Rust ever disagree about
// what bytes mean, `art_x` stops naming the same thing in two places, which
// is the whole property content addressing exists to provide.
func TestMatchesRustVectors(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			got, err := Derive(envelopeFor(v.PayloadType, v.PayloadB64))
			if err != nil {
				t.Fatalf("derive: %v", err)
			}
			if got.ArtifactID != v.ArtifactID {
				t.Errorf("artifact_id\n  got  %s\n  want %s", got.ArtifactID, v.ArtifactID)
			}
			if got.Digest != v.Digest {
				t.Errorf("digest\n  got  %s\n  want %s", got.Digest, v.Digest)
			}
		})
	}
}

// The attack the 2026-08 audit described: claim a legitimate id, upload
// unrelated bytes. Before the derivation check this was accepted and stored.
func TestSquattingAClaimedIDIsRejected(t *testing.T) {
	real := loadVectors(t).Vectors[0]
	attacker := envelopeFor(
		"application/vnd.treeship.action.v1+json",
		base64.RawURLEncoding.EncodeToString([]byte(`{"type":"treeship/action/v1","actor":"ship://attacker"}`)),
	)

	_, err := Check(attacker, real.ArtifactID, real.Digest, real.PayloadType)
	if err == nil {
		t.Fatal("attacker bytes were accepted under a victim's artifact id")
	}
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
	// Both wrong fields should be reported, not just the first.
	if !strings.Contains(err.Error(), "artifact_id") || !strings.Contains(err.Error(), "digest") {
		t.Errorf("error should name every mismatched field, got: %v", err)
	}
}

func TestHonestSubmissionIsAccepted(t *testing.T) {
	for _, v := range loadVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if _, err := Check(envelopeFor(v.PayloadType, v.PayloadB64),
				v.ArtifactID, v.Digest, v.PayloadType); err != nil {
				t.Fatalf("rejected a correct submission: %v", err)
			}
		})
	}
}

// payload_type is signed into the PAE, so a caller cannot relabel an artifact
// while keeping its id -- but it is also stored and indexed separately, and
// an unchecked copy is how a receipt gets filed as something it is not.
func TestMismatchedPayloadTypeIsRejected(t *testing.T) {
	v := loadVectors(t).Vectors[0]
	_, err := Check(envelopeFor(v.PayloadType, v.PayloadB64),
		v.ArtifactID, v.Digest, "application/vnd.treeship.session.v1+json")
	if err == nil {
		t.Fatal("accepted a payload_type that disagrees with the envelope")
	}
	if !errors.Is(err, ErrMismatch) {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestTamperedPayloadChangesTheID(t *testing.T) {
	v := loadVectors(t).Vectors[0]
	original, err := base64.RawURLEncoding.DecodeString(v.PayloadB64)
	if err != nil {
		t.Fatalf("decode vector payload: %v", err)
	}
	tampered := append([]byte{}, original...)
	tampered[len(tampered)-2] ^= 0x01

	got, err := Derive(envelopeFor(v.PayloadType,
		base64.RawURLEncoding.EncodeToString(tampered)))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if got.ArtifactID == v.ArtifactID {
		t.Fatal("a one-bit payload change produced the same artifact id")
	}
}

func TestMalformedEnvelopesAreRejectedNotDerived(t *testing.T) {
	cases := map[string]string{
		"not json":       `{`,
		"no payloadType": `{"payload":"e30"}`,
		"no payload":     `{"payloadType":"application/vnd.in-toto+json"}`,
		"bad base64":     `{"payloadType":"application/vnd.in-toto+json","payload":"!!!not base64!!!"}`,
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Derive(env); !errors.Is(err, ErrMalformed) {
				t.Fatalf("want ErrMalformed, got %v", err)
			}
		})
	}
}

// Padded base64url must derive the same id as unpadded: the decoded bytes are
// identical, and rejecting one form would break clients for no security gain.
func TestPaddedBase64DerivesTheSameID(t *testing.T) {
	v := loadVectors(t).Vectors[0]
	raw, _ := base64.RawURLEncoding.DecodeString(v.PayloadB64)
	padded := base64.URLEncoding.EncodeToString(raw)

	got, err := Derive(envelopeFor(v.PayloadType, padded))
	if err != nil {
		t.Fatalf("derive padded: %v", err)
	}
	if got.ArtifactID != v.ArtifactID {
		t.Fatalf("padding changed the id: got %s want %s", got.ArtifactID, v.ArtifactID)
	}
}

// PAE lengths are byte counts. An implementation using character counts passes
// every ASCII vector and fails only on real payloads, so this is asserted
// directly rather than left to the vector set.
func TestPAEUsesByteLengthsNotCharacterCounts(t *testing.T) {
	payload := []byte("héllo→") // 6 characters, 9 bytes
	pae := string(PAE("t", payload))
	if !strings.HasPrefix(pae, "DSSEv1 1 t 9 ") {
		t.Fatalf("PAE should use byte length 9, not character count 6; got %q", pae)
	}
}

func TestSameBytesDistinguishesFormatting(t *testing.T) {
	a := `{"payloadType":"x","payload":"e30"}`
	b := `{"payloadType": "x", "payload": "e30"}`
	if SameBytes(a, b) {
		t.Fatal("envelopes differing in whitespace are not the same stored bytes; " +
			"treating them as equal would let a re-push change what is served")
	}
	if !SameBytes(a, a) {
		t.Fatal("identical bytes reported as different")
	}
}
