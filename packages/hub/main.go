package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/treeship/hub/internal/artifacts"
	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dock"
	"github.com/treeship/hub/internal/merkle"
	"github.com/treeship/hub/internal/receipts"
	"github.com/treeship/hub/internal/ship"
	"github.com/treeship/hub/internal/verify"
)

func main() {
	database, err := db.Open()
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer database.Close()

	dockHandlers := &dock.Handlers{DB: database}
	artifactHandlers := &artifacts.Handlers{DB: database}
	verifyHandlers := &verify.Handlers{DB: database}
	merkleHandlers := &merkle.Handlers{DB: database}
	receiptHandlers := &receipts.Handlers{DB: database}
	shipHandlers := &ship.Handlers{DB: database}

	r := chi.NewRouter()

	// CORS — allow treeship.dev frontend to call the API.
	r.Use(corsMiddleware)

	// Log every request.
	r.Use(middleware.RequestID)
	r.Use(requestLogger)
	r.Use(middleware.Recoverer)

	// Dock endpoints.
	r.Get("/v1/dock/challenge", dockHandlers.Challenge)
	r.Get("/v1/dock/authorized", dockHandlers.Authorized)
	r.Post("/v1/dock/authorize", dockHandlers.Authorize)

	// Artifact endpoints.
	r.Post("/v1/artifacts", artifactHandlers.Push)
	r.Get("/v1/artifacts/{id}", artifactHandlers.Pull)

	// Workspace endpoint.
	r.Get("/v1/workspace/{dockId}", artifactHandlers.Workspace)

	// Workspace share-session endpoint: DPoP-authenticated mint of a short-lived
	// opaque token that browsers can present via ?session= on the workspace GET.
	r.Post("/v1/session", artifactHandlers.Session)

	// Verify endpoint.
	r.Get("/v1/verify/{id}", verifyHandlers.Verify)

	// Merkle endpoints.
	r.Post("/v1/merkle/checkpoint", merkleHandlers.PublishCheckpoint)
	r.Post("/v1/merkle/proof", merkleHandlers.PublishProof)
	r.Get("/v1/merkle/checkpoint/latest", merkleHandlers.GetLatestCheckpoint)
	r.Get("/v1/merkle/checkpoint/{id}", merkleHandlers.GetCheckpoint)
	r.Get("/v1/merkle/{artifactId}", merkleHandlers.GetProof)

	// Session receipt endpoints.
	// PUT is DPoP-authenticated; GET is fully public and the URL is permanent.
	r.Put("/v1/receipt/{session_id}", receiptHandlers.PutReceipt)
	r.Get("/v1/receipt/{session_id}", receiptHandlers.GetReceipt)

	// Per-ship registry endpoints (DPoP-authenticated).
	r.Get("/v1/ship/agents", shipHandlers.ListAgents)
	r.Get("/v1/ship/sessions", shipHandlers.ListSessions)

	// Well-known revocation list.
	r.Get("/.well-known/treeship/revoked.json", revokedHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("treeship hub listening on :%s", port)
	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// corsMiddleware allows the treeship.dev frontend to call the API.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "https://treeship.dev" ||
			origin == "https://www.treeship.dev" ||
			origin == "http://localhost:3000" ||
			origin == "http://localhost:2680" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
		w.Header().Set("Access-Control-Max-Age", "86400")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs method, path, status, and duration for every request.
// Query parameters are included but the `session` value (a short-lived
// workspace share token) is redacted so it never lands in access logs.
func requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		log.Printf("%s %s %d %s", r.Method, redactPath(r.URL), ww.Status(), time.Since(start))
	})
}

// redactPath returns "/path?query" with the value of any `session` query
// parameter replaced by "REDACTED". Matches case-insensitively so
// ?Session= or ?SESSION= are also redacted.
func redactPath(u *url.URL) string {
	if u.RawQuery == "" {
		return u.Path
	}
	q := u.Query()
	redacted := false
	for key := range q {
		if strings.EqualFold(key, "session") {
			q.Set(key, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path + "?" + q.Encode()
}

// revokedHandler serves GET /.well-known/treeship/revoked.json
func revokedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "max-age=86400")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"revoked":   []interface{}{},
		"signed_at": time.Now().UTC().Format(time.RFC3339),
		"version":   "1",
	})
}
