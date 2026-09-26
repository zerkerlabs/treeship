package version

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestHandlerReportsTheBuild(t *testing.T) {
	Version, Commit, BuiltAt = "0.31.10", "abc1234", "2026-09-26T00:00:00Z"
	t.Cleanup(func() { Version, Commit, BuiltAt = "", "", "" })
	rr := httptest.NewRecorder()
	Handler(rr, httptest.NewRequest("GET", "/v1/version", nil))
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("Cache-Control %q", cc)
	}
	var got Info
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("not JSON: %v: %s", err, rr.Body.String())
	}
	if got.Service != "treeship-hub" || got.Version != "0.31.10" || got.Commit != "abc1234" || got.BuiltAt != "2026-09-26T00:00:00Z" {
		t.Fatalf("unexpected: %+v", got)
	}
	if got.Go == "" {
		t.Fatalf("go version missing: %+v", got)
	}
}

func TestUnsetValuesReadDevNotEmpty(t *testing.T) {
	Version, Commit, BuiltAt = "", "", ""
	got := Current()
	if got.Version == "" || got.Commit == "" || got.BuiltAt == "" {
		t.Fatalf("empty field: %+v", got)
	}
}
