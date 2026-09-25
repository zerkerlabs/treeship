package publicurl

import (
	"testing"
)

func TestNoConfigurationKeepsTreeshipPages(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	t.Setenv(EnvHubPublicURL, "")
	if got := Artifact("art_1"); got != "https://treeship.dev/verify/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	if got := Receipt("ssn_1"); got != "https://treeship.dev/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

func TestPublicUrlNamesThePageSite(t *testing.T) {
	t.Setenv(EnvPublicURL, "https://receipts.example.com/")
	t.Setenv(EnvHubPublicURL, "https://hub.example.com")
	if got := Artifact("art_1"); got != "https://receipts.example.com/verify/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	if got := Receipt("ssn_1"); got != "https://receipts.example.com/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}

func TestHubPublicUrlAloneReturnsApiUrls(t *testing.T) {
	t.Setenv(EnvPublicURL, "")
	t.Setenv(EnvHubPublicURL, "https://hub.example.com/")
	if got := Artifact("art_1"); got != "https://hub.example.com/v1/artifacts/art_1" {
		t.Fatalf("artifact: %s", got)
	}
	if got := Receipt("ssn_1"); got != "https://hub.example.com/v1/receipt/ssn_1" {
		t.Fatalf("receipt: %s", got)
	}
}
