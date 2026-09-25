package publicurl

import (
	"net/http/httptest"
	"testing"
)

func TestProductionHostKeepsTreeshipPages(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	r := httptest.NewRequest("POST", "/v1/artifacts", nil)
	r.Host = "api.treeship.dev"
	if got := Artifact(r, "art_1"); got != "https://treeship.dev/verify/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	if got := Receipt(r, "ssn_1"); got != "https://treeship.dev/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

// Railway terminates TLS and forwards to the container with its own Host;
// the host the client used is in X-Forwarded-Host.
func TestRailwayStyleProxyHeadersKeepTreeshipPages(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	r := httptest.NewRequest("PUT", "/v1/receipt/ssn_1", nil)
	r.Host = "treeship-hub.up.railway.app"
	r.Header.Set("X-Forwarded-Host", "api.treeship.dev")
	r.Header.Set("X-Forwarded-Proto", "https")
	if got := Receipt(r, "ssn_1"); got != "https://treeship.dev/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
	if got := Artifact(r, "art_1"); got != "https://treeship.dev/verify/art_1" {
		t.Fatalf("artifact: %s", got)
	}
}

func TestLocalHubReturnsItsOwnApiUrls(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	r := httptest.NewRequest("POST", "/v1/artifacts", nil)
	r.Host = "localhost:18089"
	if got := Artifact(r, "art_1"); got != "http://localhost:18089/v1/artifacts/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	if got := Receipt(r, "ssn_1"); got != "http://localhost:18089/v1/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

func TestSelfHostedBehindProxyUsesForwardedOrigin(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	r := httptest.NewRequest("PUT", "/v1/receipt/ssn_1", nil)
	r.Host = "10.0.0.7:8080"
	r.Header.Set("X-Forwarded-Host", "hub.example.com, 10.0.0.7:8080")
	r.Header.Set("X-Forwarded-Proto", "https, http")
	if got := Receipt(r, "ssn_1"); got != "https://hub.example.com/v1/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

func TestPublicUrlEnvWinsAndTrailingSlashIsDropped(t *testing.T) {
	t.Setenv(EnvPublicURL, "https://receipts.example.com/")
	r := httptest.NewRequest("POST", "/v1/artifacts", nil)
	r.Host = "api.treeship.dev"
	if got := Artifact(r, "art_1"); got != "https://receipts.example.com/verify/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	r.Host = "localhost:18089"
	if got := Receipt(r, "ssn_1"); got != "https://receipts.example.com/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

func TestLookalikeHostIsNotTreeship(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	r := httptest.NewRequest("POST", "/v1/artifacts", nil)
	r.Host = "treeship.dev.evil.example"
	if got := Artifact(r, "art_1"); got != "http://treeship.dev.evil.example/v1/artifacts/art_1" {
		t.Fatalf("artifact: %s", got)
	}
}
