package verify

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os/exec"

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

	// Run treeship verify subprocess.
	cmd := exec.Command("treeship", "verify", id, "--format", "json")
	output, err := cmd.Output()
	if err != nil {
		// Check if treeship binary is not found.
		if _, lookErr := exec.LookPath("treeship"); lookErr != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"outcome": "error",
				"message": "verifier unavailable",
			})
			return
		}

		// treeship exited nonzero. This is a PUBLIC, unauthenticated
		// endpoint: internal verifier stderr and Go error strings are
		// implementation detail an anonymous caller has no business
		// reading (paths, versions, panic text). Log server-side, return
		// a generic verdict. The artifact is client-verifiable anyway --
		// anyone who wants detail runs `treeship verify` themselves.
		if exitErr, ok := err.(*exec.ExitError); ok && len(exitErr.Stderr) > 0 {
			log.Printf("verify %s: %s", id, string(exitErr.Stderr))
		} else {
			log.Printf("verify %s: %v", id, err)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"outcome": "error",
			"message": "verification failed",
		})
		return
	}

	// Return the JSON output directly.
	w.Header().Set("Content-Type", "application/json")
	w.Write(output)
}
