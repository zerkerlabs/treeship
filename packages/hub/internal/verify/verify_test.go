package verify

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/treeship/hub/internal/db"
)

func TestVerifyRetiredInsteadOfReturningFalseServerVerdict(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	const id = "art_retired_verify"
	if err := db.InsertArtifact(database, &db.Artifact{
		ArtifactID:   id,
		PayloadType:  "application/vnd.treeship.action.v1+json",
		EnvelopeJSON: `{"payload":"signed-bytes-live-here"}`,
		Digest:       "sha256:test",
		SignedAt:     1,
	}); err != nil {
		t.Fatalf("insert artifact: %v", err)
	}

	router := chi.NewRouter()
	router.Get("/v1/verify/{id}", (&Handlers{DB: database}).Verify)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/verify/"+id, nil))

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusGone, rec.Body.String())
	}
	var body map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["outcome"] != "retired" {
		t.Fatalf("outcome = %#v, want retired", body["outcome"])
	}
	if body["artifact_url"] != "/v1/artifacts/"+id {
		t.Fatalf("artifact_url = %#v", body["artifact_url"])
	}
}

func TestVerifyMissingArtifactStillReturnsNotFound(t *testing.T) {
	t.Setenv("TREESHIP_HUB_DB", filepath.Join(t.TempDir(), "hub.db"))
	database, err := db.Open()
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	defer database.Close()

	router := chi.NewRouter()
	router.Get("/v1/verify/{id}", (&Handlers{DB: database}).Verify)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/verify/missing", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
