package postgres

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"google.golang.org/protobuf/proto"
)

// enqueueFingerprint returns the SHA-256 of the normalized enqueue intent:
// queue, deterministic job_params encoding, and the requested max_attempts
// (or "omitted"). Each field is length-prefixed so field boundaries are
// unambiguous. execution_config is excluded because the server applies it.
func enqueueFingerprint(queue string, params *jobv1.JobParams, maxAttempts *int32) ([]byte, error) {
	paramsBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(params)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal job_params: %w", err)
	}

	h := sha256.New()
	writeField := func(b []byte) {
		var l [8]byte
		binary.BigEndian.PutUint64(l[:], uint64(len(b)))
		h.Write(l[:])
		h.Write(b)
	}

	writeField([]byte(queue))
	writeField(paramsBytes)

	if maxAttempts == nil {
		writeField([]byte{0})
	} else {
		var v [4]byte
		binary.BigEndian.PutUint32(v[:], uint32(*maxAttempts)) //nolint:gosec // value is an opaque hash input
		writeField(append([]byte{1}, v[:]...))
	}

	return h.Sum(nil), nil
}
