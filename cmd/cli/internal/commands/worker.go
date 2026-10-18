package commands

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"time"

	"connectrpc.com/connect"
	"connectrpc.com/otelconnect"
	"github.com/cenkalti/backoff/v5"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	jobv1 "github.com/wolfeidau/airunner/api/gen/proto/go/job/v1"
	"github.com/wolfeidau/airunner/cmd/cli/internal/credentials"
	"github.com/wolfeidau/airunner/internal/client"
	"github.com/wolfeidau/airunner/internal/leasereason"
	"github.com/wolfeidau/airunner/internal/telemetry"
	"github.com/wolfeidau/airunner/internal/util"
	"github.com/wolfeidau/airunner/internal/worker"
	"github.com/wolfeidau/airunner/internal/worker/lease"
	"github.com/wolfeidau/airunner/internal/worker/wal"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WorkerCmd struct {
	Server            string        `help:"Server URL" default:"https://localhost"`
	Queue             string        `help:"Queue name to process" default:"default"`
	Credential        string        `help:"Credential name (uses default if not specified)"`
	ClientTimeout     time.Duration `help:"Client timeout in seconds" default:"5m"`
	VisibilityTimeout int32         `help:"Visibility timeout in seconds (30-3600)" default:"300"`
	KeepFailedWAL     time.Duration `help:"Keep discarded or stale WALs in the failed directory for this long (0 disables)" default:"0" env:"AIRUNNER_KEEP_FAILED_WAL"`
	ArchiveRetention  time.Duration `help:"Delete archived WALs older than this at startup (0 keeps them)" default:"168h" env:"AIRUNNER_ARCHIVE_RETENTION"`
	Tracing           bool          `help:"enable tracing and metrics export (OTEL_* env)" env:"AIRUNNER_TRACING"`

	metrics *telemetry.WorkerMetrics // nil records nothing
}

// workerMetrics returns the configured instruments or no-op instruments.
func (w *WorkerCmd) workerMetrics() *telemetry.WorkerMetrics {
	if w.metrics == nil {
		return telemetry.NoopWorkerMetrics()
	}
	return w.metrics
}

// setupTelemetry initialises metrics export when --tracing is set and returns a shutdown function.
func (w *WorkerCmd) setupTelemetry(ctx context.Context, version string) func() {
	w.metrics = telemetry.NoopWorkerMetrics()
	if !w.Tracing {
		return func() {}
	}
	log.Info().Msg("Tracing is enabled")
	shutdown, err := telemetry.InitTelemetry(ctx, "airunner-worker", version)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to initialize telemetry, continuing without metrics")
		return func() {}
	}
	if m, err := telemetry.NewWorkerMetrics(otel.GetMeterProvider().Meter(meterName)); err != nil {
		log.Warn().Err(err).Msg("Failed to create worker metrics, continuing without metrics")
	} else {
		w.metrics = m
	}
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("Failed to shutdown telemetry")
		}
	}
}

const meterName = "github.com/wolfeidau/airunner"

func (w *WorkerCmd) Run(ctx context.Context, globals *Globals) error {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).
		With().Caller().Logger()

	log.Info().Str("version", globals.Version).Msg("Starting RPC server")

	log.Info().Str("queue", w.Queue).Str("server", w.Server).Msg("Worker starting")

	defer w.setupTelemetry(ctx, globals.Version)()

	// Initialize credential store and auth interceptor
	store, err := credentials.NewStore("")
	if err != nil {
		return fmt.Errorf("failed to initialize credentials: %w", err)
	}

	authInterceptor, err := credentials.NewAuthInterceptor(store, w.Credential, w.Server)
	if err != nil {
		return err
	}

	otelInterceptor, err := otelconnect.NewInterceptor()
	if err != nil {
		return fmt.Errorf("failed to create interceptor: %w", err)
	}

	config := client.Config{
		ServerURL: w.Server,
		Timeout:   w.ClientTimeout,
		Debug:     globals.Debug,
	}
	clients, err := client.NewClients(config,
		connect.WithInterceptors(authInterceptor),
		connect.WithInterceptors(otelInterceptor),
	)
	if err != nil {
		return fmt.Errorf("failed to create clients: %w", err)
	}

	// Remove WALs left by crashed workers before taking new jobs.
	report, err := wal.CleanupStale(w.walConfig(), w.KeepFailedWAL)
	if err != nil {
		log.Error().Err(err).Msg("Failed to clean up stale WALs")
	}
	log.Info().Interface("report", report).Msg("Stale WAL cleanup finished")

	if err := wal.CleanupArchive(w.walConfig().ArchiveDir, w.ArchiveRetention); err != nil {
		log.Error().Err(err).Msg("Failed to clean up archived WALs")
	}

	bkoffStrategy := backoff.NewExponentialBackOff()
	bkoffStrategy.InitialInterval = 1 * time.Second
	bkoffStrategy.MaxInterval = 10 * time.Second
	bkoffStrategy.Multiplier = 1.5
	bkoffStrategy.RandomizationFactor = 0.5

	// Start worker loop
	for {
		if globals.Debug {
			log.Debug().Msg("Looking for jobs...")
		}

		jobFound, err := w.processJob(ctx, clients)
		if err != nil {
			if isDeadlineExceeded(err) {
				continue
			}
			log.Error().Err(err).Stack().Msg("Error processing job")
			// Sleep with jitter after error to prevent thundering herd on retry
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(addJitter(5*time.Second, 0.25)):
			}
			continue
		}

		if jobFound {
			// Reset backoff when we found and processed a job
			bkoffStrategy.Reset()
			// Brief pause with jitter before next poll to prevent thundering herd
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(addJitter(1*time.Second, 0.25)):
			}
		} else {
			// No job found, use exponential backoff (already has randomization)
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(bkoffStrategy.NextBackOff()):
			}
		}
	}
}

func (w *WorkerCmd) processJob(ctx context.Context, clients *client.Clients) (bool, error) {
	// Create a context for dequeue without the client timeout
	dequeueCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Dequeue a job
	req := &jobv1.DequeueJobRequest{
		Queue:                    w.Queue,
		MaxJobs:                  1,
		VisibilityTimeoutSeconds: w.VisibilityTimeout,
	}

	stream, err := clients.Job.DequeueJob(dequeueCtx, connect.NewRequest(req))
	if err != nil {
		return false, fmt.Errorf("failed to dequeue job: %w", err)
	}
	defer stream.Close()

	// Wait for a job
	if !stream.Receive() {
		if err := stream.Err(); err != nil {
			return false, fmt.Errorf("stream error: %w", err)
		}
		return false, nil // No jobs available
	}

	return true, w.runJob(ctx, clients, w.walConfig(), stream.Msg())
}

// walConfig returns the default WAL config wired to the worker metrics.
func (w *WorkerCmd) walConfig() *wal.WALConfig {
	cfg := wal.DefaultConfig()
	cfg.Metrics = w.workerMetrics()
	return cfg
}

// runJob executes one dequeued job under a renewable lease and settles it.
func (w *WorkerCmd) runJob(ctx context.Context, clients *client.Clients, walCfg *wal.WALConfig, dequeued *jobv1.DequeueJobResponse) error {
	job := dequeued.Job
	taskToken := dequeued.TaskToken

	log.Info().Str("job_id", job.JobId).Int32("attempt", job.Attempt).Str("repository", job.JobParams.Repository).Msg("Job dequeued")

	if job.JobParams.Command == "" {
		log.Error().Str("job_id", job.JobId).Msg("No command specified for job")
		return errors.New("no command specified")
	}

	// The WAL is per (job, attempt): a redelivered attempt starts a fresh sequence space
	// and must never resend another attempt's records.
	jobWAL, err := wal.NewWAL(walCfg, job.JobId, job.Attempt)
	if err != nil {
		return fmt.Errorf("failed to create WAL: %w", err)
	}

	if err := jobWAL.Start(ctx, &grpcEventSender{clients: clients, taskToken: taskToken}); err != nil {
		_ = jobWAL.Discard(false)
		return fmt.Errorf("failed to start WAL sender: %w", err)
	}

	// Renew the lease until the job settles. When the controller aborts or the WAL sender
	// is first to see lease loss or cancellation on publish, execCtx is cancelled and
	// console-stream terminates the process group (SIGTERM, SIGKILL after 5s).
	accepted := time.Duration(dequeued.VisibilityTimeoutSeconds) * time.Second
	if accepted <= 0 {
		accepted = time.Duration(w.VisibilityTimeout) * time.Second
	}
	ctrl := lease.New(newRenewFunc(clients, taskToken), accepted, lease.WithMetrics(w.workerMetrics()))
	ctrlCtx, cancelCtrl := context.WithCancel(ctx)
	defer cancelCtrl()
	go ctrl.Run(ctrlCtx)

	execCtx, cancelExec := context.WithCancel(ctx)
	defer cancelExec()
	go func() {
		select {
		case <-ctrl.Done():
			cancelExec()
		case <-jobWAL.Failed():
			walErr := jobWAL.Err()
			if !errors.Is(walErr, wal.ErrLeaseLost) {
				// Permanent publish failure: let execution finish, the job then fails in finish().
				select {
				case <-ctrl.Done():
					cancelExec()
				case <-execCtx.Done():
				}
				return
			}
			logger := log.With().Str("job_id", job.JobId).Int32("attempt", job.Attempt).Logger()
			if isCancelled(walErr) {
				logger.Info().Msg("job cancelled; stopping execution")
			} else {
				logger.Warn().Err(walErr).Msg("lease lost on publish; stopping execution")
			}
			ctrl.Stop()
			cancelExec()
		case <-execCtx.Done():
		}
	}()

	// EventBatcher writes to the WAL with fsync; the WAL sender publishes asynchronously.
	batcher := worker.NewEventBatcher(job.ExecutionConfig, func(event *jobv1.JobEvent) error {
		return jobWAL.Append(ctx, event)
	})
	executeErr := worker.NewJobExecutor(taskToken, batcher).Execute(execCtx, job)
	cancelExec()

	r := &jobRun{clients: clients, walCfg: walCfg, job: job, taskToken: taskToken, wal: jobWAL, ctrl: ctrl, keep: w.KeepFailedWAL > 0, metrics: w.workerMetrics()}
	defer ctrl.Stop()
	return r.finish(ctx, executeErr)
}

// jobRun holds the state needed to settle a finished execution.
type jobRun struct {
	clients   *client.Clients
	walCfg    *wal.WALConfig
	job       *jobv1.Job
	taskToken string
	wal       wal.WAL
	ctrl      *lease.Controller
	keep      bool // keep discarded WALs in failed/ for diagnosis
	metrics   *telemetry.WorkerMetrics
}

// finish settles the job after execution returns: flush the WAL, then complete, fail,
// or abandon the job depending on what the lease and the publish path report.
func (r *jobRun) finish(ctx context.Context, executeErr error) error {
	if r.leaseLost() {
		r.abandonLost("lease lost", nil)
		return nil
	}

	flushCtx, cancel := context.WithTimeout(ctx, min(30*time.Second, r.ctrl.Remaining()))
	flushErr := r.wal.Flush(flushCtx)
	cancel()

	switch {
	case flushErr == nil:
	case errors.Is(flushErr, wal.ErrLeaseLost) || r.leaseLost():
		r.abandonLost("lease lost", flushErr)
		return nil
	case errors.Is(flushErr, wal.ErrPermanent):
		// The server will never accept the remaining events: fail the job with the
		// acknowledged prefix and keep the log marked incomplete.
		log.Error().Err(flushErr).Str("job_id", r.job.JobId).Msg("Permanent event publish failure")
		executeErr = fmt.Errorf("event log incomplete (acknowledged through sequence %d): %w", r.wal.Acked(), flushErr)
		err := r.complete(ctx, executeErr)
		r.discard()
		return err
	case r.wal.Pending() > 0:
		// Expiry redelivers the job; completing now would lose the pending events.
		r.ctrl.Stop()
		r.abandon(abandonFlushTimeout, "events could not be published before the lease budget ran out")
		return nil
	}

	if err := r.complete(ctx, executeErr); err != nil {
		// The server may have committed the completion; keep the WAL for diagnosis.
		log.Warn().Err(err).Str("job_id", r.job.JobId).Msg("complete response lost; WAL kept in failed/ for diagnosis")
		if derr := r.wal.Discard(true); derr != nil {
			log.Error().Err(derr).Str("job_id", r.job.JobId).Msg("Failed to discard WAL")
		}
		return err
	}
	r.archive(ctx)
	return nil
}

// leaseLost reports whether the lease controller aborted or the WAL sender saw lease loss.
func (r *jobRun) leaseLost() bool {
	return r.ctrl.Err() != nil || errors.Is(r.wal.Err(), wal.ErrLeaseLost)
}

// cancelled reports whether the controller or the WAL sender saw the job cancelled.
func (r *jobRun) cancelled(errs ...error) bool {
	if errors.Is(r.ctrl.Err(), lease.ErrCancelled) || isCancelled(r.wal.Err()) {
		return true
	}
	for _, err := range errs {
		if isCancelled(err) {
			return true
		}
	}
	return false
}

// abandonLost abandons the job as cancelled when any evidence says so, else as lease loss.
func (r *jobRun) abandonLost(detail string, err error) {
	if r.cancelled(err) {
		r.abandon(abandonCancelled, "job cancelled")
		return
	}
	r.abandon(abandonLeaseLost, detail)
}

// complete sends CompleteJob with the acknowledged event prefix. Lease loss on completion
// abandons the job without reporting an error.
func (r *jobRun) complete(ctx context.Context, executeErr error) error {
	jobResult := &jobv1.JobResult{
		JobId:       r.job.JobId,
		Success:     executeErr == nil,
		StartedAt:   r.job.UpdatedAt, // Job was marked RUNNING when dequeued
		CompletedAt: timestamppb.Now(),
	}
	if executeErr != nil {
		log.Error().Err(executeErr).Str("job_id", r.job.JobId).Msg("Job execution failed")
		jobResult.ExitCode = 1
		var exitErr *worker.ExitError
		if errors.As(executeErr, &exitErr) {
			jobResult.ExitCode = util.AsInt32(exitErr.Code)
		}
		jobResult.ErrorMessage = executeErr.Error()
	} else {
		log.Info().Str("job_id", r.job.JobId).Msg("Job executed successfully")
	}

	_, err := r.clients.Job.CompleteJob(ctx, connect.NewRequest(&jobv1.CompleteJobRequest{
		TaskToken:          r.taskToken,
		JobResult:          jobResult,
		FinalEventSequence: r.wal.Acked(),
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeFailedPrecondition {
			r.abandonLost("lease lost on completion", err)
			return nil
		}
		return fmt.Errorf("failed to complete job: %w", err)
	}

	log.Info().Str("job_id", r.job.JobId).Bool("success", jobResult.Success).Msg("Job completed")
	return nil
}

// Abandon reasons, used as the reason attribute of worker.jobs.abandoned.
const (
	abandonLeaseLost    = "lease_lost"
	abandonCancelled    = "cancelled"
	abandonFlushTimeout = "flush_timeout"
	abandonOther        = "other"
)

// abandon drops the WAL without completing or releasing the job; lease expiry redelivers it.
// reason is one of the abandon* constants; detail is for the log.
func (r *jobRun) abandon(reason, detail string) {
	if r.metrics != nil {
		r.metrics.JobsAbandoned.Add(context.Background(), 1, metric.WithAttributes(attribute.String("reason", reason)))
	}
	if reason == abandonCancelled {
		log.Info().
			Str("job_id", r.job.JobId).
			Int32("attempt", r.job.Attempt).
			Int("pending", r.wal.Pending()).
			Msg("job cancelled")
		r.discard()
		return
	}
	log.Warn().
		Str("job_id", r.job.JobId).
		Int32("attempt", r.job.Attempt).
		Int("pending", r.wal.Pending()).
		Str("reason", reason).
		Str("detail", detail).
		Msg("Abandoning job without completing, lease expiry will redeliver")
	r.discard()
}

func (r *jobRun) discard() {
	if err := r.wal.Discard(r.keep); err != nil {
		log.Error().Err(err).Str("job_id", r.job.JobId).Msg("Failed to discard WAL")
	}
}

// archive stops the WAL after a confirmed completion and archives it when enabled.
func (r *jobRun) archive(ctx context.Context) {
	if !r.walCfg.ArchiveOnComplete {
		r.discard()
		return
	}
	if err := r.wal.Stop(ctx); err != nil {
		log.Error().Err(err).Str("job_id", r.job.JobId).Msg("Failed to stop WAL")
		return
	}
	if err := r.wal.Archive(ctx, r.walCfg.ArchiveDir); err != nil {
		log.Error().Err(err).Str("job_id", r.job.JobId).Msg("Failed to archive WAL")
	}
}

// newRenewFunc adapts UpdateJob to the lease controller, mapping FailedPrecondition to lease.ErrLost.
func newRenewFunc(clients *client.Clients, taskToken string) lease.RenewFunc {
	return func(ctx context.Context, requested time.Duration) (time.Duration, error) {
		resp, err := clients.Job.UpdateJob(ctx, connect.NewRequest(&jobv1.UpdateJobRequest{
			TaskToken:                taskToken,
			VisibilityTimeoutSeconds: util.AsInt32(int(requested / time.Second)),
		}))
		if err != nil {
			if isCancelled(err) {
				return 0, fmt.Errorf("%w: %w", lease.ErrCancelled, err)
			}
			if connect.CodeOf(err) == connect.CodeFailedPrecondition {
				return 0, fmt.Errorf("%w: %w", lease.ErrLost, err)
			}
			return 0, err
		}
		return time.Duration(resp.Msg.VisibilityTimeoutSeconds) * time.Second, nil
	}
}

// isCancelled reports whether err is a FailedPrecondition carrying the cancelled lease reason.
func isCancelled(err error) bool {
	var connErr *connect.Error
	if !errors.As(err, &connErr) || connErr.Code() != connect.CodeFailedPrecondition {
		return false
	}
	return connErr.Meta().Get(leasereason.Header) == leasereason.Cancelled
}

func isDeadlineExceeded(err error) bool {
	var connErr *connect.Error
	if errors.As(err, &connErr) {
		return connErr.Code() == connect.CodeDeadlineExceeded
	}
	return false
}

// addJitter adds random jitter to a duration to prevent thundering herd.
// Returns a duration between base*(1-jitterFactor) and base*(1+jitterFactor).
// For jitterFactor=0.25, returns a value between 75% and 125% of base.
func addJitter(base time.Duration, jitterFactor float64) time.Duration {
	if jitterFactor <= 0 {
		return base
	}
	// Calculate jitter range: base * (1 - jitterFactor) to base * (1 + jitterFactor)
	min := float64(base) * (1.0 - jitterFactor)
	max := float64(base) * (1.0 + jitterFactor)
	//nolint:gosec // G404: Using math/rand for timing jitter is safe and appropriate
	jittered := min + rand.Float64()*(max-min)
	return time.Duration(jittered)
}

// grpcEventSender publishes each WAL batch with one unary PublishJobEvents call.
type grpcEventSender struct {
	clients   *client.Clients
	taskToken string
}

// Send implements wal.EventSender
func (s *grpcEventSender) Send(ctx context.Context, events []*jobv1.JobEvent) (wal.Ack, error) {
	resp, err := s.clients.Events.PublishJobEvents(ctx, connect.NewRequest(&jobv1.PublishJobEventsRequest{
		TaskToken: s.taskToken,
		Events:    events,
	}))
	if err != nil {
		return wal.Ack{}, classifyPublishError(err)
	}
	return wal.Ack{Attempt: resp.Msg.Attempt, Through: resp.Msg.AcknowledgedThroughSequence}, nil
}

// classifyPublishError wraps a publish error with the wal error class for its connect code.
// Unlisted codes stay transient and are retried.
func classifyPublishError(err error) error {
	switch connect.CodeOf(err) {
	case connect.CodeFailedPrecondition:
		return fmt.Errorf("%w: %w", wal.ErrLeaseLost, err)
	case connect.CodeInvalidArgument, connect.CodeAlreadyExists, connect.CodeResourceExhausted:
		return fmt.Errorf("%w: %w", wal.ErrPermanent, err)
	default:
		return err
	}
}
