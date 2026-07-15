package verify

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/treeship/hub/internal/db"
)

type Handlers struct {
	DB *sql.DB
}

// Verify handles GET /v1/verify/:id
func (h *Handlers) Verify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "missing artifact id"})
		return
	}

	// Check artifact exists.
	_, err := db.GetArtifact(h.DB, id)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "artifact not found"})
		return
	}

	// Server-side verification is intentionally retired. The old handler
	// shelled out to `treeship verify <id>`, but the subprocess had no access
	// to the Hub's artifact bytes or a caller's trust roots. It therefore
	// returned HTTP 200 + outcome:error for valid Hub artifacts in production,
	// while any verdict it could produce would have represented the server's
	// trust policy rather than the verifier's. The Hub is transport/index;
	// callers fetch signed bytes and verify them against their own roots.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusGone)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"outcome":      "retired",
		"message":      "server-side verification is retired; fetch the signed artifact and verify it locally",
		"artifact_url": "/v1/artifacts/" + id,
	})
}
