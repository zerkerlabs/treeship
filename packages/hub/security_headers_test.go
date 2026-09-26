package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func headersFor(t *testing.T, mutate func(*http.Request)) http.Header {
	t.Helper()
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	req := httptest.NewRequest("GET", "/v1/stats", nil)
	mutate(req)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Header()
}

const wantHSTS = "max-age=63072000; includeSubDomains"

func TestHSTSOnProxiedHTTPS(t *testing.T) {
	h := headersFor(t, func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https") })
	if got := h.Get("Strict-Transport-Security"); got != wantHSTS {
		t.Fatalf("HSTS %q", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("nosniff %q", got)
	}
}

func TestHSTSOnDirectTLS(t *testing.T) {
	h := headersFor(t, func(r *http.Request) { r.TLS = &tls.ConnectionState{} })
	if got := h.Get("Strict-Transport-Security"); got != wantHSTS {
		t.Fatalf("HSTS %q", got)
	}
}

func TestHSTSTakesTheFirstForwardedProto(t *testing.T) {
	h := headersFor(t, func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "https, http") })
	if got := h.Get("Strict-Transport-Security"); got != wantHSTS {
		t.Fatalf("HSTS %q", got)
	}
}

func TestNoHSTSOverPlainHTTPButStillNosniff(t *testing.T) {
	h := headersFor(t, func(_ *http.Request) {})
	if got := h.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS set over plain http: %q", got)
	}
	if got := h.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("nosniff %q", got)
	}
	h = headersFor(t, func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") })
	if got := h.Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS set for forwarded http: %q", got)
	}
}
