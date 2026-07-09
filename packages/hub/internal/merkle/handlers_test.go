package merkle

import (
	"crypto/ed25519"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
)

// AUD-18: PublishCheckpoint used to store signer/signature/public_key with no
// verification at all. verifyCheckpointSignature is the gate that fixes it:
// the signature must verify over the canonical bytes, and every structured
// field the hub stores must be one that was actually signed.
func TestVerifyCheckpointSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	root := "sha256:abcd1234"
	signer := "key_hub"
	signedAt := "2026-07-08T00:00:00Z"
	var treeSize int64 = 10
	// v3 canonical layout: v3|cv|mv|algo|zk|index|root|tree_size|height|signer|signed_at
	canonical := strings.Join([]string{
		"v3", "3", "2", "", "", "6",
		root, strconv.FormatInt(treeSize, 10), "4", signer, signedAt,
	}, "|")
	sig := ed25519.Sign(priv, []byte(canonical))

	valid := checkpointRequest{
		Root:      root,
		TreeSize:  treeSize,
		SignedAt:  signedAt,
		Signer:    signer,
		Signature: base64.RawURLEncoding.EncodeToString(sig),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub),
		Canonical: canonical,
	}
	if err := verifyCheckpointSignature(&valid); err != nil {
		t.Fatalf("a validly-signed checkpoint must verify: %v", err)
	}

	// Tampered canonical: the signature no longer applies.
	tampered := valid
	tampered.Canonical = strings.Replace(canonical, root, "sha256:evil", 1)
	if verifyCheckpointSignature(&tampered) == nil {
		t.Fatal("a tampered canonical must fail signature verification")
	}

	// The AUD-18/AUD-11 shadow move: the signature is valid, but the attacker
	// sets the stored `signer` to a victim's id that is NOT the one inside the
	// signed canonical. Must be rejected so the hub cannot serve an unsigned
	// signer.
	spoofedSigner := valid
	spoofedSigner.Signer = "key_victim"
	if verifyCheckpointSignature(&spoofedSigner) == nil {
		t.Fatal("a signer not present in the signed canonical must be rejected")
	}

	// A stored root that was not the one signed is likewise rejected.
	spoofedRoot := valid
	spoofedRoot.Root = "sha256:unsigned"
	if verifyCheckpointSignature(&spoofedRoot) == nil {
		t.Fatal("a root not present in the signed canonical must be rejected")
	}

	// Wrong-length / malformed key and signature fail closed.
	badKey := valid
	badKey.PublicKey = "not-base64!!"
	if verifyCheckpointSignature(&badKey) == nil {
		t.Fatal("malformed public_key must be rejected")
	}
}
