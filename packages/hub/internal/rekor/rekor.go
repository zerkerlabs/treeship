package rekor

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/treeship/hub/internal/db"
)

const rekorURL = "https://rekor.sigstore.dev/api/v1/log/entries"

// Anchor submits a hashedrekord entry to Rekor and stores the logIndex.
// Best-effort: logs error and returns nil if Rekor is unavailable.
func Anchor(database *sql.DB, artifactID, digest, envelopeJSON, shipPubKeyHex string) *int64 {
	// Strip "sha256:" prefix if present.
	hashValue := digest
	if strings.HasPrefix(hashValue, "sha256:") {
		hashValue = strings.TrimPrefix(hashValue, "sha256:")
	}

	// Extract the first signature from envelope_json.
	var envelope struct {
		Signatures []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal([]byte(envelopeJSON), &envelope); err != nil {
		log.Printf("rekor: failed to parse envelope_json: %v", err)
		return nil
	}
	if len(envelope.Signatures) == 0 {
		log.Printf("rekor: no signatures in envelope")
		return nil
	}

	sigContent := envelope.Signatures[0].Sig

	// Decode hex ship public key and base64 encode for Rekor.
	pubKeyBytes, err := hexDecode(shipPubKeyHex)
	if err != nil {
		log.Printf("rekor: failed to decode ship_public_key: %v", err)
		return nil
	}
	pubKeyB64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

	body := map[string]interface{}{
		"kind":       "hashedrekord",
		"apiVersion": "0.0.1",
		"spec": map[string]interface{}{
			"data": map[string]interface{}{
				"hash": map[string]string{
					"algorithm": "sha256",
					"value":     hashValue,
				},
			},
			"signature": map[string]interface{}{
				"content": sigContent,
				"publicKey": map[string]string{
					"content": pubKeyB64,
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		log.Printf("rekor: failed to marshal body: %v", err)
		return nil
	}

	// AUD-23: the default http.Post has NO timeout. A slow or hung
	// rekor.sigstore.dev (outage, or an on-path attacker holding the socket)
	// blocked artifacts.Push indefinitely, each blocked call pinning a
	// Throttle(100) slot -> full-hub DoS during a Rekor outage. Bound the whole
	// round-trip with a context + client timeout, and LimitReader the response
	// so a hostile server cannot stream unbounded data into memory. (Moving
	// anchoring fully off the request path into an async worker is the deeper
	// fix, tracked as a follow-up.)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, rekorURL, bytes.NewReader(bodyBytes))
	if err != nil {
		log.Printf("rekor: build request failed: %v", err)
		return nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(httpReq)
	if err != nil {
		log.Printf("rekor: POST failed: %v", err)
		return nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		log.Printf("rekor: failed to read response: %v", err)
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("rekor: non-2xx response (%d): %s", resp.StatusCode, string(respBody))
		return nil
	}

	// Response is a map of UUID -> entry. Extract logIndex from the first entry.
	var result map[string]json.RawMessage
	if err := json.Unmarshal(respBody, &result); err != nil {
		log.Printf("rekor: failed to parse response: %v", err)
		return nil
	}

	for _, entryRaw := range result {
		var entry struct {
			LogIndex int64 `json:"logIndex"`
		}
		if err := json.Unmarshal(entryRaw, &entry); err != nil {
			log.Printf("rekor: failed to parse entry: %v", err)
			return nil
		}

		if err := db.SetRekorIndex(database, artifactID, entry.LogIndex); err != nil {
			log.Printf("rekor: failed to store logIndex: %v", err)
		}

		idx := entry.LogIndex
		return &idx
	}

	log.Printf("rekor: empty response")
	return nil
}

func hexDecode(s string) ([]byte, error) {
	b := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		if i+2 > len(s) {
			return nil, fmt.Errorf("odd hex string length")
		}
		hi := unhex(s[i])
		lo := unhex(s[i+1])
		if hi == 0xFF || lo == 0xFF {
			return nil, fmt.Errorf("invalid hex char")
		}
		b[i/2] = hi<<4 | lo
	}
	return b, nil
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	default:
		return 0xFF
	}
}
