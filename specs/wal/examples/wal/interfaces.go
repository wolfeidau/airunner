// Package wal provides example interfaces for the Write-Ahead Log system
// This is a reference implementation showing the key interfaces
package wal

import (
	"context"
	"time"

	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
)

// WAL provides durable event persistence with async retry
type WAL interface {
	// Append writes event to disk (synchronous, with fsync)
	// Returns error if disk write or fsync fails
	Append(ctx context.Context, event *jobv1.JobEvent) error

	// Start begins async sender goroutine
	// The sender will continuously retry failed sends with exponential backoff
	Start(ctx context.Context, sender EventSender) error

	// Stop flushes pending events and stops async sender
	// Blocks until all pending events are sent or context is cancelled
	Stop(ctx context.Context) error

	// Archive compresses WAL file and moves to archive directory
	// Uses zstd level 3 compression (~70% reduction)
	Archive(ctx context.Context, archiveDir string) error
}

// EventSender sends events to the server
// This interface allows decoupling WAL from transport mechanism
type EventSender interface {
	// Send transmits events to the server
	// Returns error if send fails (WAL will retry)
	Send(ctx context.Context, events []*jobv1.JobEvent) error
}

// WALConfig configures WAL behavior
type WALConfig struct {
	// WALDir is the directory for active WAL files
	WALDir string

	// ArchiveDir is the directory for compressed archives
	ArchiveDir string

	// RetentionDays is how long to keep archived files
	RetentionDays int

	// FlushInterval is how often the async sender checks for unsent events
	FlushInterval time.Duration

	// RetryBackoff configures exponential backoff for failed sends
	RetryBackoff BackoffConfig

	// ArchiveOnComplete enables automatic archiving after job completion
	ArchiveOnComplete bool
}

// BackoffConfig configures exponential backoff retry
type BackoffConfig struct {
	// InitialInterval is the first retry delay (e.g., 1 second)
	InitialInterval time.Duration

	// MaxInterval is the maximum retry delay (e.g., 60 seconds)
	MaxInterval time.Duration

	// Multiplier controls backoff growth (e.g., 2.0 for exponential)
	Multiplier float64
}

// Example usage:
//
//   cfg := &WALConfig{
//       WALDir:            "~/.airunner/wal",
//       ArchiveDir:        "~/.airunner/archive",
//       RetentionDays:     30,
//       FlushInterval:     100 * time.Millisecond,
//       ArchiveOnComplete: true,
//       RetryBackoff: BackoffConfig{
//           InitialInterval: 1 * time.Second,
//           MaxInterval:     60 * time.Second,
//           Multiplier:      2.0,
//       },
//   }
//
//   wal, err := NewWAL(cfg, jobID)
//   defer wal.Stop(ctx)
//
//   sender := &grpcEventSender{stream: stream, taskToken: token}
//   wal.Start(ctx, sender)
//
//   // EventBatcher callback
//   batcher := NewEventBatcher(config, func(event *jobv1.JobEvent) error {
//       return wal.Append(ctx, event)
//   })
