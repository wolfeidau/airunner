import { useState, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import { createConnectTransport } from "@connectrpc/connect-web";
import { createClient } from "@connectrpc/connect";
import { TransportProvider, useQuery } from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { listJobs } from "../../api/gen/proto/es/job/v1/job-JobService_connectquery";
import { usePageContext } from "../lib/context";
import {
  JobState,
  EventType,
  StreamType,
  JobEventsService,
  type JobEvent,
  type OutputBatchEvent,
} from "../../api/gen/proto/es/job/v1/job_pb";
import { timestampToJsDate } from "../lib/proto_convert";

import "./app.css";
import "./dashboard.css";
import type { Timestamp } from "@bufbuild/protobuf/wkt";

// Custom hook to stream job events in real-time
function useJobEventStream(
  jobId: string,
  transport: ReturnType<typeof createConnectTransport>,
) {
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [isConnecting, setIsConnecting] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [jobCompleted, setJobCompleted] = useState(false);

  useEffect(() => {
    const abortController = new AbortController();

    async function streamEvents() {
      try {
        const eventsClient = createClient(JobEventsService, transport);
        const stream = eventsClient.streamJobEvents(
          {
            jobId,
            fromSequence: 0n,
            fromTimestamp: 0n,
            eventFilter: [],
          },
          { signal: abortController.signal },
        );

        setIsConnecting(false);

        for await (const response of stream) {
          if (response.event) {
            setEvents((prev) => [...prev, response.event]);

            // Detect job completion and close stream
            if (response.event.eventType === EventType.PROCESS_END) {
              setJobCompleted(true);
              break; // Close stream after job completes
            }
          }
        }
      } catch (err: unknown) {
        if (err instanceof Error && err.name !== "AbortError") {
          setError(err.message || "Stream error");
          setIsConnecting(false);
        } else if (!(err instanceof Error)) {
          setError("Stream error");
          setIsConnecting(false);
        }
      }
    }

    streamEvents();

    return () => abortController.abort();
  }, [jobId, transport]);

  return { events, isConnecting, error, jobCompleted };
}

// OutputBatch Renderer - unpacks batched console output
function OutputBatchRenderer({
  batch,
  startTimeMs,
}: {
  batch: OutputBatchEvent;
  startTimeMs: number;
}) {
  // Pre-calculate the batch start offset once (more efficient)
  const batchStartOffsetMs = Number(batch.firstTimestampMs) - startTimeMs;

  return (
    <>
      {batch.outputs.map((output) => {
        // Reconstruct absolute timestamp from batch
        const outputTimestampMs =
          Number(batch.firstTimestampMs) + output.timestampDeltaMs;
        const outputTime = new Date(outputTimestampMs);
        const timestamp = outputTime.toLocaleTimeString("en-US", {
          hour12: false,
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        });

        // Calculate offset from job start using pre-calculated batch offset + delta
        const offsetMs = batchStartOffsetMs + output.timestampDeltaMs;
        const offsetSeconds = (offsetMs / 1000).toFixed(1);

        // Decode bytes to string
        const text = new TextDecoder("utf-8", { fatal: false }).decode(
          output.output,
        );

        // Style based on stream type (stdout vs stderr)
        const className =
          output.streamType === StreamType.STDERR
            ? "output-stderr"
            : "output-stdout";

        return (
          <div
            key={`${batch.firstTimestampMs}-${output.timestampDeltaMs}`}
            className={`output-line ${className}`}
          >
            <span className="output-offset">+{offsetSeconds}s</span>
            <span className="output-timestamp">[{timestamp}]</span>
            <span className="output-text">{text}</span>
          </div>
        );
      })}
    </>
  );
}

// EventItem - renders individual events based on type
function EventItem({
  event,
  startTimeMs,
}: {
  event: JobEvent;
  startTimeMs: number;
}) {
  const timestamp = event.timestamp
    ? timestampToJsDate(event.timestamp).toLocaleTimeString("en-US", {
        hour12: false,
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      })
    : "";

  // Calculate offset from job start for lifecycle events
  const eventTimeMs = event.timestamp
    ? timestampToJsDate(event.timestamp).getTime()
    : 0;
  const offsetMs = eventTimeMs - startTimeMs;
  const offsetSeconds = (offsetMs / 1000).toFixed(1);

  switch (event.eventType) {
    case EventType.PROCESS_START:
      if (event.eventData.case === "processStart") {
        const start = event.eventData.value;
        return (
          <div className="event-lifecycle event-start">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] Process started (PID: {start.pid})
          </div>
        );
      }
      break;

    case EventType.PROCESS_END:
      if (event.eventData.case === "processEnd") {
        const end = event.eventData.value;
        const status = end.exitCode === 0 ? "SUCCESS" : "FAILED";
        const statusClass =
          end.exitCode === 0 ? "event-success" : "event-failed";
        return (
          <div className={`event-lifecycle ${statusClass}`}>
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] {status} - Process ended (Exit Code: {end.exitCode})
          </div>
        );
      }
      break;

    case EventType.PROCESS_ERROR:
      if (event.eventData.case === "processError") {
        const error = event.eventData.value;
        return (
          <div className="event-lifecycle event-error">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] ERROR: {error.errorMessage}
          </div>
        );
      }
      break;

    case EventType.OUTPUT_BATCH:
      if (event.eventData.case === "outputBatch") {
        return (
          <OutputBatchRenderer
            batch={event.eventData.value}
            startTimeMs={startTimeMs}
          />
        );
      }
      break;

    case EventType.HEARTBEAT:
      // Skip heartbeat events (not requested by user)
      return null;

    // Git clone events
    case EventType.GIT_CLONE_START:
      if (event.eventData.case === "gitCloneStart") {
        const gitStart = event.eventData.value;
        return (
          <div className="event-lifecycle event-start">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] 📦 Git clone started: {gitStart.repository}
            {gitStart.branch && ` (branch: ${gitStart.branch})`}
            {gitStart.commit && ` (commit: ${gitStart.commit})`}
          </div>
        );
      }
      break;

    case EventType.GIT_CLONE_END:
      if (event.eventData.case === "gitCloneEnd") {
        const gitEnd = event.eventData.value;
        const shortSha =
          gitEnd.commitSha.length > 8
            ? gitEnd.commitSha.slice(0, 8)
            : gitEnd.commitSha;
        return (
          <div className="event-lifecycle event-success">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] ✅ Git clone completed (SHA: {shortSha}, Duration:{" "}
            {gitEnd.cloneDuration
              ? `${(Number(gitEnd.cloneDuration.seconds) + Number(gitEnd.cloneDuration.nanos) / 1e9).toFixed(1)}s`
              : "unknown"}
            )
          </div>
        );
      }
      break;

    case EventType.GIT_CLONE_ERROR:
      if (event.eventData.case === "gitCloneError") {
        const gitErr = event.eventData.value;
        return (
          <div className="event-lifecycle event-error">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] ❌ Git clone failed: {gitErr.errorMessage}
          </div>
        );
      }
      break;

    // Container lifecycle events
    case EventType.CONTAINER_CREATE:
      if (event.eventData.case === "containerCreate") {
        const create = event.eventData.value;
        const shortId =
          create.containerId.length > 12
            ? create.containerId.slice(0, 12)
            : create.containerId;
        return (
          <div className="event-lifecycle event-start">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] 🐳 Container created (ID: {shortId}, Image: {create.image})
          </div>
        );
      }
      break;

    case EventType.CONTAINER_REMOVE:
      if (event.eventData.case === "containerRemove") {
        const remove = event.eventData.value;
        const shortId =
          remove.containerId.length > 12
            ? remove.containerId.slice(0, 12)
            : remove.containerId;
        return (
          <div className="event-lifecycle">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] 🗑️ Container removed (ID: {shortId})
          </div>
        );
      }
      break;

    // Image pull events
    case EventType.IMAGE_PULL_START:
      if (event.eventData.case === "imagePullStart") {
        const pullStart = event.eventData.value;
        return (
          <div className="event-lifecycle event-start">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] 📥 Pulling image: {pullStart.image}
          </div>
        );
      }
      break;

    case EventType.IMAGE_PULL_PROGRESS:
      if (event.eventData.case === "imagePullProgress") {
        const progress = event.eventData.value;
        const percentage =
          progress.totalBytes > 0
            ? (
                (Number(progress.currentBytes) / Number(progress.totalBytes)) *
                100
              ).toFixed(1)
            : "0.0";
        return (
          <div className="event-lifecycle">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] 📥 {progress.status}: {percentage}% ({progress.currentBytes}/
            {progress.totalBytes} bytes)
          </div>
        );
      }
      break;

    case EventType.IMAGE_PULL_COMPLETE:
      if (event.eventData.case === "imagePullComplete") {
        const pullComplete = event.eventData.value;
        const duration = pullComplete.pullDuration
          ? `${(Number(pullComplete.pullDuration.seconds) + Number(pullComplete.pullDuration.nanos) / 1e9).toFixed(1)}s`
          : "";
        return (
          <div className="event-lifecycle event-success">
            <span className="output-offset">+{offsetSeconds}s</span>[{timestamp}
            ] ✅ Image pull completed: {pullComplete.image}
            {duration && ` (Duration: ${duration})`}
          </div>
        );
      }
      break;

    default:
      return null;
  }

  return null;
}

// EventsConsole - scrollable event container with auto-scroll
function EventsConsole({ events }: { events: JobEvent[] }) {
  const consoleEndRef = useRef<HTMLDivElement>(null);

  // Calculate job start time from first event
  const startTimeMs =
    events.length > 0 && events[0].timestamp
      ? timestampToJsDate(events[0].timestamp).getTime()
      : Date.now();

  // Auto-scroll to bottom when new events arrive
  useEffect(() => {
    consoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  });

  return (
    <div className="events-console">
      {events.map((event) => (
        <EventItem
          key={event.sequence}
          event={event}
          startTimeMs={startTimeMs}
        />
      ))}
      <div ref={consoleEndRef} />
    </div>
  );
}

// Job Events View component (Phase 3 - with streaming, Phase 4 will add full rendering)
function JobEventsView({
  jobId,
  transport,
}: {
  jobId: string;
  transport: ReturnType<typeof createConnectTransport>;
}) {
  const { events, isConnecting, error, jobCompleted } = useJobEventStream(
    jobId,
    transport,
  );

  return (
    <div className="events-container">
      <div className="events-header">
        <button
          type="button"
          className="btn-back"
          onClick={() => {
            window.location.hash = "";
          }}
        >
          ← Back to Jobs
        </button>
        <h2 className="events-title">Job: {jobId.slice(0, 12)}</h2>
      </div>

      {/* Job completion banner */}
      {jobCompleted && (
        <div className="events-banner events-banner-completed">
          Job Completed
        </div>
      )}

      {/* Loading state */}
      {isConnecting && (
        <div className="events-loading">
          <div className="spinner"></div>
          <p>Connecting to event stream...</p>
        </div>
      )}

      {/* Error state */}
      {error && (
        <div className="events-error">
          <p>Failed to load events: {error}</p>
          <button
            type="button"
            onClick={() => {
              window.location.hash = "";
            }}
          >
            Close
          </button>
        </div>
      )}

      {/* Empty state */}
      {!isConnecting && !error && events.length === 0 && (
        <div className="events-empty">
          <p>No events yet. Waiting for job to start...</p>
        </div>
      )}

      {/* Events console (Phase 4 - full rendering) */}
      {!isConnecting && !error && events.length > 0 && (
        <EventsConsole events={events} />
      )}
    </div>
  );
}

function Dashboard() {
  const { data } = useQuery(listJobs, {});
  const user = usePageContext();
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);

  // Hash routing: listen for URL hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash;
      if (hash.startsWith("#job-")) {
        setSelectedJobId(hash.substring(5)); // Remove '#job-' prefix
      } else {
        setSelectedJobId(null);
      }
    };

    // Handle initial load
    handleHashChange();

    // Listen for hash changes (browser back/forward buttons)
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  // Sort jobs by creation date, newest first
  const sortedJobs = (data?.jobs || []).sort((a, b) => {
    const timeA = timestampToJsDate(a.createdAt);
    const timeB = timestampToJsDate(b.createdAt);
    return timeB.getTime() - timeA.getTime();
  });

  const getStateColor = (state: JobState): string => {
    switch (state) {
      case JobState.SCHEDULED:
        return "state-scheduled";
      case JobState.RUNNING:
        return "state-running";
      case JobState.COMPLETED:
        return "state-completed";
      case JobState.FAILED:
        return "state-failed";
      case JobState.CANCELLED:
        return "state-cancelled";
      default:
        return "state-unspecified";
    }
  };

  const getStateLabel = (state: JobState): string => {
    switch (state) {
      case JobState.SCHEDULED:
        return "Scheduled";
      case JobState.RUNNING:
        return "Running";
      case JobState.COMPLETED:
        return "Completed";
      case JobState.FAILED:
        return "Failed";
      case JobState.CANCELLED:
        return "Cancelled";
      default:
        return "Unknown";
    }
  };

  const formatDate = (timestamp: Timestamp | undefined): string => {
    if (!timestamp) return "-";
    const date = timestampToJsDate(timestamp);
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(date);
  };

  return (
    <div className="dashboard-container">
      {/* Top Bar */}
      <div className="dashboard-topbar">
        <div className="topbar-left">
          <h1 className="topbar-title">airunner</h1>
        </div>
        <div className="topbar-right">
          <span className="user-name">{user?.name || "User"}</span>
          <a href="/logout" className="btn-logout">
            Logout
          </a>
        </div>
      </div>

      {/* Conditional rendering: show event view or job list */}
      {selectedJobId ? (
        <JobEventsView jobId={selectedJobId} transport={finalTransport} />
      ) : (
        <div className="dashboard-content">
          {/* CLI Section */}
          <div className="cli-section">
            <div className="cli-header">
              <h2>Submit a Job</h2>
              <p className="cli-subtitle">
                Use the CLI to submit jobs to your queue
              </p>
            </div>
            <div className="cli-command">
              <code>
                $ airunner-cli submit --server=https://localhost:8993
                --queue=default github.com/example/repo
              </code>
            </div>
          </div>

          {/* Jobs Table */}
          <div className="jobs-section">
            <h2 className="section-title">Recent Jobs</h2>
            {sortedJobs.length === 0 ? (
              <div className="empty-state">
                <p>No jobs yet. Use the CLI above to submit your first job.</p>
              </div>
            ) : (
              <div className="table-wrapper">
                <table className="jobs-table">
                  <thead>
                    <tr>
                      <th>Job ID</th>
                      <th>Repository</th>
                      <th>Created</th>
                      <th className="cell-status">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedJobs.map((job) => (
                      <tr
                        key={job.jobId}
                        className="job-row job-row-clickable"
                        onClick={() => {
                          window.location.hash = `#job-${job.jobId}`;
                        }}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" || e.key === " ") {
                            e.preventDefault();
                            window.location.hash = `#job-${job.jobId}`;
                          }
                        }}
                        tabIndex={0}
                        aria-label={`View details for job ${job.jobId?.slice(0, 8)}`}
                      >
                        <td className="cell-job-id">
                          <code>{job.jobId?.slice(0, 8)}</code>
                        </td>
                        <td className="cell-repo">
                          {job.jobParams?.repository || "-"}
                        </td>
                        <td className="cell-date">
                          {formatDate(job.createdAt)}
                        </td>
                        <td className="cell-status">
                          <span
                            className={`status-badge ${getStateColor(job.state)}`}
                          >
                            {getStateLabel(job.state)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

const queryClient = new QueryClient();
const finalTransport = createConnectTransport({
  baseUrl: "https://localhost:8993",
});

// Initialize on load
const appElement = document.getElementById("app");
if (!appElement) throw new Error("App element not found");
const root = createRoot(appElement);
root.render(
  <TransportProvider transport={finalTransport}>
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  </TransportProvider>,
);
