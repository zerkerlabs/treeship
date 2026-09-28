package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func corsHeadersFor(origin string) http.Header {
	h := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=86400, immutable")
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/v1/receipt/ssn_x", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Header()
}

// The allowed origin is echoed on responses a shared cache may store, so
// the cache key must include the Origin: Vary: Origin on every response.
func TestVaryOriginAccompaniesTheEchoedOrigin(t *testing.T) {
	for _, origin := range []string{"https://treeship.dev", "https://evil.example", ""} {
		h := corsHeadersFor(origin)
		if !strings.Contains(strings.Join(h.Values("Vary"), ","), "Origin") {
			t.Fatalf("origin %q: no Vary: Origin, headers %v", origin, h)
		}
		acao := h.Get("Access-Control-Allow-Origin")
		if origin == "https://treeship.dev" && acao != origin {
			t.Fatalf("allowed origin not echoed: %q", acao)
		}
		if origin != "https://treeship.dev" && acao != "" {
			t.Fatalf("origin %q was echoed: %q", origin, acao)
		}
	}
	if m := corsHeadersFor("").Get("Access-Control-Allow-Methods"); !strings.Contains(m, "DELETE") || !strings.Contains(m, "HEAD") {
		t.Fatalf("allowed methods missing DELETE/HEAD: %q", m)
	}
}
