// Package leasereason defines the response header that tells clients why a
// lease-fenced RPC failed. It is dependency-free so the CLI can import it.
package leasereason

const (
	// Header carries the reason on FailedPrecondition errors from lease-fenced calls.
	Header = "Airunner-Lease-Reason"
	// Cancelled means the job was cancelled; the worker should stop it.
	Cancelled = "cancelled"
)
