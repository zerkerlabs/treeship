package merkle

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/zerkerlabs/treeship/packages/hub/internal/db"
)

func TestAgeSecondsIsNowMinusSignedAt(t *testing.T) {
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	if got := ageSeconds("2026-09-26T11:59:00Z", now); got == nil || *got != 60 {
		t.Fatalf("age: %v", got)
	}
	if got := ageSeconds("2026-09-27T00:00:00Z", now); got == nil || *got != 0 {
		t.Fatalf("future signed_at floors at zero: %v", got)
	}
	if got := ageSeconds("yesterday", now); got != nil {
		t.Fatalf("unparseable signed_at must be null, got %v", *got)
	}
}

func TestLatestCheckpointResponseCarriesAgeAndEveryField(t *testing.T) {
	cp := &db.MerkleCheckpoint{ID: 7, RootHex: "ab", TreeSize: 9, SignedAt: "2026-08-06T00:00:00Z", SignerKeyID: "key_x"}
	age := int64(42)
	body, err := json.Marshal(latestCheckpointResponse{MerkleCheckpoint: cp, AgeSeconds: &age})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	if m["age_seconds"] != float64(42) || m["root"] != "ab" || m["tree_size"] != float64(9) || m["signer"] != "key_x" {
		t.Fatalf("unexpected: %s", body)
	}
}
