package artifacts

import (
	"encoding/json"
	"testing"
)

// parseSignedAt used to return time.Now() on every failure path, and its
// string branch never parsed at all -- a valid RFC3339 timestamp was silently
// replaced by server time. These pin both halves of the fix: real values are
// read, and unreadable ones are rejected rather than fabricated.
func TestParseSignedAt(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int64
		ok   bool
	}{
		{"unix integer", `1786397740`, 1786397740, true},
		{"rfc3339", `"2026-08-10T21:35:40Z"`, 1786397740, true},
		{"rfc3339 nano", `"2026-08-10T21:35:40.123Z"`, 1786397740, true},
		{"absent", ``, 0, false},
		{"null", `null`, 0, false},
		{"garbage string", `"not-a-time"`, 0, false},
		{"object", `{"t":1}`, 0, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseSignedAt(json.RawMessage(tc.raw))
			if ok != tc.ok {
				t.Fatalf("ok = %v, want %v", ok, tc.ok)
			}
			if ok && got != tc.want {
				t.Fatalf("got %d, want %d", got, tc.want)
			}
			if !ok && got != 0 {
				t.Fatalf("rejected input must return 0, not a fabricated %d", got)
			}
		})
	}
}
