package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
)

// The public read endpoints are unauthenticated and each one currently scans
// every artifact of a payload type, so the per-IP limit in front of them is
// load-bearing, not decorative. These assert the two properties that make it
// worth having: it actually stops a caller, and it stops that caller only.

func limitedRouter(t *testing.T) chi.Router {
	t.Helper()
	r := chi.NewRouter()
	r.Group(func(pub chi.Router) {
		pub.Use(httprate.Limit(
			60, time.Minute,
			httprate.WithKeyFuncs(httprate.KeyByRealIP),
			httprate.WithLimitHandler(rateLimited),
		))
		pub.Get("/v1/agents", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	// Outside the group: must not share the public budget.
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	return r
}

func get(t *testing.T, r chi.Router, path, ip string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":12345"
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec.Code
}

func TestPublicEndpointsAreRateLimitedPerIP(t *testing.T) {
	r := limitedRouter(t)

	allowed := 0
	for i := 0; i < 70; i++ {
		if get(t, r, "/v1/agents?agent=agent://x", "203.0.113.1") == http.StatusOK {
			allowed++
		}
	}
	if allowed != 60 {
		t.Fatalf("expected exactly 60 requests allowed in the window, got %d", allowed)
	}

	// The limit must be per client, or one noisy caller denies everyone --
	// which converts a rate limiter into the outage it was meant to prevent.
	if code := get(t, r, "/v1/agents?agent=agent://x", "203.0.113.2"); code != http.StatusOK {
		t.Fatalf("a second IP was rejected on its first request (got %d); "+
			"the limit is global, not per-client", code)
	}
}

// Health checks sharing the public budget is how a rate-limited service gets
// killed by its own orchestrator: the probe 429s and the instance is declared
// dead while it is merely busy.
func TestHealthEndpointDoesNotShareThePublicBudget(t *testing.T) {
	r := limitedRouter(t)
	for i := 0; i < 70; i++ {
		get(t, r, "/v1/agents?agent=agent://x", "203.0.113.3")
	}
	if code := get(t, r, "/healthz", "203.0.113.3"); code != http.StatusOK {
		t.Fatalf("/healthz returned %d after the public budget was spent", code)
	}
}

func TestRateLimitedResponseIsJSON(t *testing.T) {
	rec := httptest.NewRecorder()
	rateLimited(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("want 429, got %d", rec.Code)
	}
	// Clients parse one error shape. httprate's default body is plain text,
	// which would make the limiter the one response a caller has to special-case.
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("want application/json, got %q", ct)
	}
	if body := rec.Body.String(); body == "" || body[0] != '{' {
		t.Fatalf("want a JSON object body, got %q", rec.Body.String())
	}
}

// `ready` is what takes an instance out of rotation before its connections
// are cut. If it defaulted to true, a starting process would advertise itself
// as able to serve before the listener existed.
func TestReadinessDefaultsToNotReady(t *testing.T) {
	if ready.Load() {
		t.Fatal("ready defaults to true; a starting process would accept traffic " +
			"before the listener is up")
	}
}
