package postgres

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/wolfeidau/airunner/internal/store"
)

const (
	taskTokenVersion     = "v1"       // Task token format version for future compatibility
	maxEventPayloadBytes = 350 * 1024 // 350KB safety margin for event payloads
)

// taskToken is a stateless token containing job_id, queue, and receipt_handle.
// Format: base64url(version|job_id|queue|receipt_handle|hmac_signature)
// The HMAC signature provides integrity protection against tampering.
// This is an internal implementation detail and should not be exported.
type taskToken struct {
	JobID         string
	Queue         string
	ReceiptHandle string // UUID from jobs.receipt_handle
}

// encodeTaskToken creates a signed stateless task token.
// Format: base64url(v1|job_id|queue|receipt_handle|hmac_sha256_signature)
// The HMAC signature prevents token tampering and provides defense in depth.
func (s *JobStore) encodeTaskToken(jobID, queue, receiptHandle string) string {
	// Build the data payload with version prefix
	data := fmt.Sprintf("%s|%s|%s|%s", taskTokenVersion, jobID, queue, receiptHandle)

	// Compute HMAC-SHA256 signature
	h := hmac.New(sha256.New, s.cfg.TokenSigningSecret)
	h.Write([]byte(data))
	sig := hex.EncodeToString(h.Sum(nil))

	// Append signature to data
	signed := fmt.Sprintf("%s|%s", data, sig)

	return base64.URLEncoding.EncodeToString([]byte(signed))
}

// decodeTaskToken extracts and verifies components from a signed task token.
// Validates HMAC signature to prevent tampering using constant-time comparison.
func (s *JobStore) decodeTaskToken(token string) (*taskToken, error) {
	if token == "" {
		return nil, fmt.Errorf("%w: token cannot be empty", store.ErrInvalidTaskToken)
	}

	// Base64 decode
	data, err := base64.URLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid encoding: %v", store.ErrInvalidTaskToken, err)
	}

	// Split into components: version|job_id|queue|receipt_handle|signature
	parts := strings.Split(string(data), "|")
	if len(parts) != 5 {
		return nil, fmt.Errorf("%w: expected 5 parts (version|job_id|queue|receipt|sig), got %d", store.ErrInvalidTaskToken, len(parts))
	}

	version, jobID, queue, receiptHandle, providedSig := parts[0], parts[1], parts[2], parts[3], parts[4]

	// Validate version
	if version != taskTokenVersion {
		return nil, fmt.Errorf("%w: unsupported version %s (expected %s)", store.ErrInvalidTaskToken, version, taskTokenVersion)
	}

	// Validate non-empty components
	if jobID == "" || queue == "" || receiptHandle == "" {
		return nil, fmt.Errorf("%w: empty component in token", store.ErrInvalidTaskToken)
	}

	// Recompute HMAC signature
	payload := fmt.Sprintf("%s|%s|%s|%s", version, jobID, queue, receiptHandle)
	h := hmac.New(sha256.New, s.cfg.TokenSigningSecret)
	h.Write([]byte(payload))
	expectedSig := hex.EncodeToString(h.Sum(nil))

	// Constant-time comparison to prevent timing attacks
	if !hmac.Equal([]byte(expectedSig), []byte(providedSig)) {
		return nil, fmt.Errorf("%w: invalid signature", store.ErrInvalidTaskToken)
	}

	return &taskToken{
		JobID:         jobID,
		Queue:         queue,
		ReceiptHandle: receiptHandle,
	}, nil
}
