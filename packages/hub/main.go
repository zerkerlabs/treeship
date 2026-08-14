package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/treeship/hub/internal/agents"
	"github.com/treeship/hub/internal/artifacts"
	"github.com/treeship/hub/internal/db"
	"github.com/treeship/hub/internal/dock"
	"github.com/treeship/hub/internal/merkle"
	"github.com/treeship/hub/internal/receipts"
	"github.com/treeship/hub/internal/ship"
	"github.com/treeship/hub/internal/stats"
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
	agentHandlers := &agents.Handlers{DB: database}
	statsHandlers := &stats.Handlers{DB: database}

	r := chi.NewRouter()

	// CORS — allow treeship.dev frontend to call the API.
	r.Use(corsMiddleware)

	// Two different limits, because they stop two different things.
	//
	// Throttle caps *concurrency*: at most 100 requests in flight. It does
	// nothing about rate -- one client can hold all 100 slots and keep
	// refilling them as they drain, which is how the public endpoints were
	// cheap to exhaust.
	//
	// httprate caps *rate per client key*. The key is the real client IP, so
	// one caller cannot spend the whole budget for everyone. Applied globally
	// here; the public read endpoints below take a tighter one because they
	// are unauthenticated and each one does real work.
	r.Use(middleware.Throttle(100))
	r.Use(httprate.Limit(
		600, time.Minute,
		httprate.WithKeyFuncs(httprate.KeyByRealIP),
		httprate.WithLimitHandler(rateLimited),
	))

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
	r.Post("/v1/merkle/consistency", merkleHandlers.PublishConsistency)
	r.Get("/v1/merkle/checkpoint/latest", merkleHandlers.GetLatestCheckpoint)
	r.Get("/v1/merkle/checkpoint/{id}", merkleHandlers.GetCheckpoint)
	// Register the literal /consistency GET before the {artifactId} catch-all
	// below, or "consistency" would be matched as an artifact id.
	r.Get("/v1/merkle/consistency", merkleHandlers.GetConsistency)
	r.Get("/v1/merkle/{artifactId}", merkleHandlers.GetProof)

	// Session receipt endpoints.
	// PUT is DPoP-authenticated; GET is fully public and the URL is permanent.
	r.Put("/v1/receipt/{session_id}", receiptHandlers.PutReceipt)
	r.Get("/v1/receipt/{session_id}", receiptHandlers.GetReceipt)

	// Per-ship registry endpoints (DPoP-authenticated).
	r.Get("/v1/ship/agents", shipHandlers.ListAgents)
	r.Get("/v1/ship/sessions", shipHandlers.ListSessions)

	// The public read endpoints, grouped so they share a tighter budget.
	//
	// These are unauthenticated and each one currently scans every artifact of
	// a payload type and JSON-parses each envelope, so a request here costs
	// far more than the flat global limit assumes. 60/min per IP keeps normal
	// resolution comfortable -- a client resolving one agent makes one call --
	// while making a scan loop expensive to sustain.
	//
	// This bounds the *rate*, not the per-request cost. The cost itself is
	// audit items 11 and 21: derive indexed columns at ingestion so the
	// resolver filters in SQL instead of loading the table. Until that lands
	// this is a limit in front of a known-expensive path, which is worth
	// saying out loud rather than filing as done.
	r.Group(func(pub chi.Router) {
		pub.Use(httprate.Limit(
			60, time.Minute,
			httprate.WithKeyFuncs(httprate.KeyByRealIP),
			httprate.WithLimitHandler(rateLimited),
		))

		// Agent resolver: resolve an agent URI to its verifiable bundle (cards
		// + revocations as raw signed envelopes; the client re-verifies).
		pub.Get("/v1/agents", agentHandlers.Resolve)

		// Agent transparency log: an agent's append-only receipt history
		// (metadata + Merkle anchors only, never payloads). The client
		// re-verifies.
		pub.Get("/v1/agents/log", agentHandlers.Log)
		pub.Get("/v1/agents/history", agentHandlers.History)
		pub.Get("/v1/agents/match", agentHandlers.Match)

		// Public adoption metrics: counts only, never identifiers. Cached 5 min.
		pub.Get("/v1/stats", statsHandlers.Stats)
	})

	// Well-known revocation list.
	r.Get("/.well-known/treeship/revoked.json", revokedHandler(database))

	// Liveness and readiness are different questions and need different
	// answers. /healthz says the process is up; a load balancer uses it to
	// decide whether to restart. /readyz says the process can serve, which
	// during a deploy is false before the database is reachable and false
	// again the moment shutdown begins -- that is what takes an instance out
	// of rotation *before* its connections are cut, rather than after.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"draining"}`))
			return
		}
		// Readiness that never checks anything is just liveness with a longer
		// name. Ping the database, since serving without it is not ready.
		ctx, cancel := context.WithTimeout(req.Context(), 2*time.Second)
		defer cancel()
		if err := database.PingContext(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"database unavailable"}`))
			return
		}
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// AUD-20: an explicit server with timeouts. `http.ListenAndServe` sets
	// none, so a handful of connections that dribble request headers a byte at
	// a time (Slowloris) each held a Throttle(100) slot forever and froze the
	// service. ReadHeaderTimeout is the direct fix; the others bound slow
	// bodies, slow responses, and idle keep-alives. Per-IP rate limiting now
	// sits alongside the global Throttle, above.
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Serve in the background so the main goroutine can wait for a signal.
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("treeship hub listening on :%s", port)
		ready.Store(true)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-serveErr:
		log.Fatalf("server error: %v", err)
	case sig := <-stop:
		// A deploy sends SIGTERM. Without this the process died immediately
		// and every in-flight request was cut mid-write -- including artifact
		// pushes, where the client had already been told nothing and the
		// insert may or may not have landed.
		log.Printf("received %s, draining", sig)

		// Fail readiness first so the load balancer stops sending new work
		// while the existing work finishes. Shutdown alone closes listeners
		// but says nothing to anything upstream still routing to us.
		ready.Store(false)

		ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			// The grace period expired with requests still running. Say so:
			// a truncated response looks identical to a network fault from
			// the client side, and this is the only place that knows better.
			log.Printf("graceful shutdown timed out after %s, forcing close: %v",
				shutdownGrace, err)
			_ = srv.Close()
		}
		log.Printf("shutdown complete")
	}
}

// shutdownGrace bounds how long in-flight requests get after SIGTERM.
//
// Kept under the 30s most orchestrators wait before SIGKILL, so the process
// finishes on its own terms rather than being killed mid-drain.
const shutdownGrace = 20 * time.Second

// ready gates /readyz. False until the listener is up, and false again the
// moment a shutdown signal arrives.
var ready atomic.Bool

// rateLimited answers a throttled request in the same JSON shape as every
// other error here, so a client parses one format rather than special-casing
// the limiter's default plain-text body.
func rateLimited(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	_, _ = w.Write([]byte(`{"error":"rate limit exceeded, retry shortly"}`))
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
		if strings.EqualFold(key, "session") || strings.EqualFold(key, "device_code") {
			q.Set(key, "REDACTED")
			redacted = true
		}
	}
	if !redacted {
		return u.Path + "?" + u.RawQuery
	}
	return u.Path + "?" + q.Encode()
}

// Revocation entries are small; this bounds the scan and the response. A
// deployment that outgrows it needs the derived `kind` column (audit item 21),
// not a bigger number here.
// receiptPayloadType is the MIME type of treeship receipt envelopes; grant
// revocations are receipts.
const receiptPayloadType = "application/vnd.treeship.receipt.v1+json"

const revocationListLimit = 1000

// revokedHandler serves GET /.well-known/treeship/revoked.json
//
// # What changed, and why there is still no Hub signature
//
// This used to return a hardcoded empty list carrying a fresh `signed_at`,
// with `Cache-Control: max-age=86400`. Three problems in nine lines: the list
// was always empty regardless of what had been revoked, `signed_at` named a
// signature that did not exist, and a verifier that trusted it would cache
// "nothing is revoked" for a day.
//
// It now serves real revocations, and it still does not sign them -- because
// it does not need to and cannot honestly. The Hub holds no signing key, and
// `grant_revocation.v1` receipts are **already DSSE-signed by the grantor**.
// Serving the envelopes lets a client verify each one against the key the
// grant names, which is the same check the local resolver runs. A Hub
// signature over a summary would add a party to trust and prove strictly
// less: it would attest that the Hub said this, not that the grantor did.
//
// That is also the Hub's stated role -- it "stores immutable bytes, serves
// lookup indices and proofs, and never supplies trust verdicts".
//
// So the field is `generated_at`, not `signed_at`. The list is not signed; the
// entries are, individually, and a client that skips verifying them has
// learned nothing.
func revokedHandler(database *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Short, and deliberately not 24h. A stale revocation list is a
		// withdrawn grant still reading as live, so caching it for a day
		// converts a revocation into a day-long grace period for whoever
		// holds the revoked grant.
		w.Header().Set("Cache-Control", "max-age=300")

		artifacts, truncated, err := db.ListArtifactsByPayloadTypeLimit(
			database, receiptPayloadType, revocationListLimit)
		if err != nil {
			log.Printf("revocation list query failed: %v", err)
			// 503, not an empty 200. An empty list is indistinguishable from
			// "nothing is revoked", and answering a revocation query with a
			// confident wrong answer is worse than failing.
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": "revocation list temporarily unavailable",
			})
			return
		}

		revoked := make([]map[string]any, 0, len(artifacts))
		for _, a := range artifacts {
			kind, payload, ok := receiptKindAndPayload(a.EnvelopeJSON)
			if !ok || kind != "grant_revocation.v1" {
				continue
			}
			grantID, _ := payload["grant_id"].(string)
			if grantID == "" {
				continue
			}
			revoked = append(revoked, map[string]any{
				"grant_id":   grantID,
				"grantor":    payload["grantor"],
				"revoked_at": payload["revoked_at"],
				"reason":     payload["reason"],
				// The signed bytes. A client MUST verify this against the
				// grantor rather than trusting the fields above, which this
				// server could have written.
				"envelope":    json.RawMessage(a.EnvelopeJSON),
				"artifact_id": a.ArtifactID,
			})
		}

		body := map[string]any{
			"version":      "2",
			"generated_at": time.Now().UTC().Format(time.RFC3339),
			"revoked":      revoked,
			// Silent truncation on a revocation list would drop revocations a
			// client needed and look identical to their not existing.
			"truncated": truncated,
			"note": "Entries are individually DSSE-signed by the grantor. This list is " +
				"NOT signed by the hub -- verify each envelope against the grantor key " +
				"before honoring it. Absence from this list is not proof a grant is live.",
		}
		if truncated {
			body["truncation_warning"] = "more revocations exist than were returned; " +
				"this list is incomplete and must not be treated as exhaustive"
		}
		_ = json.NewEncoder(w).Encode(body)
	}
}

// receiptKindAndPayload pulls `kind` and `payload` out of a receipt envelope.
//
// Returns ok=false rather than partial data: a revocation whose envelope will
// not decode cannot be evaluated, and emitting it with missing fields would
// put an entry on the list that no client can verify.
func receiptKindAndPayload(envelopeJSON string) (string, map[string]any, bool) {
	var env struct {
		Payload string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(envelopeJSON), &env); err != nil {
		return "", nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(env.Payload, "="))
	if err != nil {
		return "", nil, false
	}
	var stmt struct {
		Kind    string         `json:"kind"`
		Payload map[string]any `json:"payload"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return "", nil, false
	}
	return stmt.Kind, stmt.Payload, true
}
