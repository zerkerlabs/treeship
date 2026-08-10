// Package hubclient is a Go client for the Treeship Hub API.
//
// It exists so a Go service -- Gateway Rooms being the first -- can publish
// receipts without shelling out to the Rust CLI or hand-rolling DPoP.
//
// # What the Hub is, and is not
//
// The Hub stores and serves. It does not grade trust. `PutReceipt` authenticates
// the *caller* via DPoP; it does not verify a signature over the receipt body,
// and it never will -- a Hub that stamps a verdict becomes an authority you have
// to trust, which is the thing Treeship exists to remove.
//
// Verification happens at the reader, against the signed envelopes at
// `GET /v1/artifacts/{id}`, using keys the reader pinned. So publishing a
// receipt here makes it *available*, not *verified*. If you want readers to be
// able to check it, publish the artifacts too.
//
// # Usage
//
//	c, err := hubclient.New(hubclient.Config{HubID: id, SecretHex: secret})
//	url, err := c.PutReceipt(ctx, sessionID, receiptJSON)
package hubclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/treeship/hub/pkg/dpop"
)

// DefaultEndpoint is the hosted Hub.
const DefaultEndpoint = "https://api.treeship.dev"

// maxReceiptBytes mirrors the server's cap. Checked client-side so an
// oversized body fails with a clear message instead of a 413 after upload.
const maxReceiptBytes = 10 << 20

// Config configures a Client.
type Config struct {
	// HubID is the dock id from `treeship hub attach`.
	HubID string
	// SecretHex is the dock's 32-byte Ed25519 seed, hex-encoded.
	SecretHex string
	// Endpoint defaults to DefaultEndpoint.
	Endpoint string
	// HTTPClient defaults to a client with a 30s timeout. Supply your own to
	// control transport, proxies, or retry middleware.
	HTTPClient *http.Client
}

// Client talks to a Treeship Hub. Safe for concurrent use.
type Client struct {
	signer   *dpop.Signer
	endpoint string
	http     *http.Client
}

// New builds a Client. Fails fast on a bad key rather than at first request:
// a service that starts healthy and cannot authenticate is harder to diagnose
// than one that refuses to start.
func New(cfg Config) (*Client, error) {
	signer, err := dpop.NewSigner(cfg.HubID, cfg.SecretHex)
	if err != nil {
		return nil, err
	}
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	httpc := cfg.HTTPClient
	if httpc == nil {
		httpc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{
		signer:   signer,
		endpoint: strings.TrimSuffix(endpoint, "/"),
		http:     httpc,
	}, nil
}

// APIError is a non-2xx response from the Hub.
type APIError struct {
	StatusCode int
	Message    string
	Op         string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("hubclient: %s: %d %s", e.Op, e.StatusCode, e.Message)
}

// PutReceipt uploads a session receipt and returns its public URL.
//
// The endpoint is idempotent per session id: a second PUT for the same session
// replaces the first. That is a **whole-document overwrite**, so two writers
// racing on one session will lose one of the writes. If you are emitting
// per-event, accumulate into an authoritative log on your side and PUT the
// composed document -- do not PUT per event.
//
// `sessionID` must match the `session.id` inside `receiptJSON`; the server
// rejects a mismatch rather than letting one session overwrite another's slot.
func (c *Client) PutReceipt(ctx context.Context, sessionID string, receiptJSON []byte) (string, error) {
	if sessionID == "" {
		return "", fmt.Errorf("hubclient: session id is required")
	}
	if len(receiptJSON) == 0 {
		return "", fmt.Errorf("hubclient: receipt body is empty")
	}
	if len(receiptJSON) > maxReceiptBytes {
		return "", fmt.Errorf("hubclient: receipt is %d bytes, over the %d-byte limit",
			len(receiptJSON), maxReceiptBytes)
	}
	// Catch the id mismatch here: the server's 400 is correct but arrives
	// after a full upload, and the message is easy to misread as "bad JSON".
	var probe struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
	}
	if err := json.Unmarshal(receiptJSON, &probe); err != nil {
		return "", fmt.Errorf("hubclient: receipt is not valid JSON: %w", err)
	}
	if probe.Session.ID != "" && probe.Session.ID != sessionID {
		return "", fmt.Errorf(
			"hubclient: session id %q does not match session.id %q in the receipt",
			sessionID, probe.Session.ID)
	}

	url := c.endpoint + "/v1/receipt/" + sessionID
	body, err := c.do(ctx, "PUT", url, receiptJSON, "put receipt")
	if err != nil {
		return "", err
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(body, &out); err == nil && out.URL != "" {
		return out.URL, nil
	}
	// The Hub's public receipt URL is derivable, so a response shape change
	// degrades to a correct URL rather than an error.
	return "https://treeship.dev/receipt/" + sessionID, nil
}

// GetReceipt fetches a published receipt. Public: no authentication, and the
// request is sent unsigned.
func (c *Client) GetReceipt(ctx context.Context, sessionID string) ([]byte, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("hubclient: session id is required")
	}
	return c.do(ctx, "GET", c.endpoint+"/v1/receipt/"+sessionID, nil, "get receipt")
}

// GetArtifact fetches a signed DSSE envelope by artifact id.
//
// This is what a verifier needs. A receipt is a rendering with no signatures
// in it; the envelopes are the evidence. Public and unauthenticated.
func (c *Client) GetArtifact(ctx context.Context, artifactID string) ([]byte, error) {
	if artifactID == "" {
		return nil, fmt.Errorf("hubclient: artifact id is required")
	}
	return c.do(ctx, "GET", c.endpoint+"/v1/artifacts/"+artifactID, nil, "get artifact")
}

// do issues one request, signing it when the endpoint requires DPoP.
func (c *Client) do(ctx context.Context, method, url string, body []byte, op string) ([]byte, error) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, fmt.Errorf("hubclient: %s: %w", op, err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// GETs on public endpoints are unsigned. Signing them would burn a jti
	// per read for no benefit -- and jti is a finite, single-use resource.
	if method != "GET" {
		if err := c.signer.Sign(req); err != nil {
			return nil, fmt.Errorf("hubclient: %s: %w", op, err)
		}
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("hubclient: %s: %w", op, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxReceiptBytes))
	if err != nil {
		return nil, fmt.Errorf("hubclient: %s: read response: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(respBody))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(respBody, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, &APIError{StatusCode: resp.StatusCode, Message: msg, Op: op}
	}
	return respBody, nil
}
