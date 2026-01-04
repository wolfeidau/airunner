import { useState, useEffect, useRef, useMemo } from "react";
import { createRoot } from "react-dom/client";
import { createClient } from "@connectrpc/connect";
import {
  TransportProvider,
  useQuery,
  useTransport,
} from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { listJobs } from "../../api/gen/proto/es/job/v1/job-JobService_connectquery";
import {
  listCredentials,
  importCredential,
  revokeCredential,
} from "../../api/gen/proto/es/principal/v1/principal-CredentialService_connectquery";
import { useMutation } from "@connectrpc/connect-query";
import type { Credential } from "../../api/gen/proto/es/principal/v1/principal_pb";
import { createConnectTransport } from "@connectrpc/connect-web";
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
function useJobEventStream(jobId: string) {
  const [events, setEvents] = useState<JobEvent[]>([]);
  const [isConnecting, setIsConnecting] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [jobCompleted, setJobCompleted] = useState(false);

  // Get transport from provider
  const transport = useTransport();

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
function JobEventsView({ jobId }: { jobId: string }) {
  const { events, isConnecting, error, jobCompleted } =
    useJobEventStream(jobId);

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

// Import credential form with inline success message
function ImportCredentialForm({ onSuccess }: { onSuccess: () => void }) {
  const [name, setName] = useState("");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [description, setDescription] = useState("");
  const [result, setResult] = useState<{
    principalId: string;
    orgId: string;
    name: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Use Connect RPC mutation
  const mutation = useMutation(importCredential);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setResult(null);

    try {
      const response = await mutation.mutateAsync({
        name,
        publicKeyPem,
        description,
      });

      setResult({
        principalId: response.principalId,
        orgId: response.orgId,
        name: response.name,
      });
      setName("");
      setPublicKeyPem("");
      setDescription("");
      onSuccess();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Import failed");
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <div className="import-form">
      <h3>Import Worker Credential</h3>
      <p className="import-subtitle">
        Paste the public key from <code>airunner-cli init</code> output
      </p>

      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label htmlFor="cred-name">Name</label>
          <input
            id="cred-name"
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g., production-workers"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="cred-pubkey">Public Key (PEM)</label>
          <textarea
            id="cred-pubkey"
            value={publicKeyPem}
            onChange={(e) => setPublicKeyPem(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
            required
          />
        </div>

        <div className="form-group">
          <label htmlFor="cred-desc">Description (optional)</label>
          <input
            id="cred-desc"
            type="text"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="e.g., Workers for production environment"
          />
        </div>

        <button
          type="submit"
          className="btn-primary"
          disabled={mutation.isPending}
        >
          {mutation.isPending ? "Importing..." : "Import Credential"}
        </button>
      </form>

      {error && (
        <div className="import-error">
          <p>Error: {error}</p>
        </div>
      )}

      {result && (
        <div className="import-success">
          <p>
            <strong>Credential imported successfully!</strong>
          </p>
          <div className="result-field">
            <span>Principal ID:</span>
            <code>{result.principalId}</code>
            <button
              type="button"
              className="btn-copy"
              onClick={() => copyToClipboard(result.principalId)}
            >
              Copy
            </button>
          </div>
          <div className="result-field">
            <span>Org ID:</span>
            <code>{result.orgId}</code>
            <button
              type="button"
              className="btn-copy"
              onClick={() => copyToClipboard(result.orgId)}
            >
              Copy
            </button>
          </div>
          <div className="result-command">
            <span>Run this command to complete setup:</span>
            <code>
              airunner-cli credentials update {result.name} --org-id{" "}
              {result.orgId} --principal-id {result.principalId}
            </code>
            <button
              type="button"
              className="btn-copy"
              onClick={() =>
                copyToClipboard(
                  `airunner-cli credentials update ${result.name} --org-id ${result.orgId} --principal-id ${result.principalId}`,
                )
              }
            >
              Copy
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// Credentials table with revoke functionality
function CredentialsTable({
  credentials,
  currentPrincipalId,
  onRevoke,
}: {
  credentials: Credential[];
  currentPrincipalId: string;
  onRevoke: (principalId: string, name: string) => void;
}) {
  const formatDate = (dateStr: string | undefined): string => {
    if (!dateStr) return "Never";
    try {
      return new Date(dateStr).toLocaleDateString("en-US", {
        year: "numeric",
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return "-";
    }
  };

  const truncateFingerprint = (fp: string | undefined): string => {
    if (!fp) return "-";
    return fp.length > 12 ? `${fp.slice(0, 12)}...` : fp;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const getTypeBadgeClass = (type: string): string => {
    switch (type) {
      case "user":
        return "type-user";
      case "worker":
        return "type-worker";
      case "service":
        return "type-service";
      default:
        return "";
    }
  };

  return (
    <div className="table-wrapper">
      <table className="credentials-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Type</th>
            <th>Fingerprint</th>
            <th>Created</th>
            <th>Last Used</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {credentials.map((cred) => (
            <tr key={cred.principalId}>
              <td className="cell-name">{cred.name}</td>
              <td className="cell-type">
                <span className={`type-badge ${getTypeBadgeClass(cred.type)}`}>
                  {cred.type}
                </span>
              </td>
              <td className="cell-fingerprint">
                {cred.fingerprint ? (
                  <button
                    type="button"
                    className="fingerprint-code"
                    onClick={() => copyToClipboard(cred.fingerprint)}
                    title="Click to copy"
                  >
                    {truncateFingerprint(cred.fingerprint)}
                  </button>
                ) : (
                  <span className="no-fingerprint">-</span>
                )}
              </td>
              <td className="cell-date">{formatDate(cred.createdAt)}</td>
              <td className="cell-date">{formatDate(cred.lastUsedAt)}</td>
              <td className="cell-actions">
                {cred.type === "worker" &&
                cred.principalId !== currentPrincipalId ? (
                  <button
                    type="button"
                    className="btn-revoke"
                    onClick={() => onRevoke(cred.principalId, cred.name)}
                  >
                    Revoke
                  </button>
                ) : cred.principalId === currentPrincipalId ? (
                  <span className="self-badge">You</span>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// Main credentials view combining form and table
function CredentialsView() {
  const user = usePageContext();

  // Use Connect RPC query for listing
  const { data, isLoading, error, refetch } = useQuery(listCredentials, {
    principalType: "",
  });

  // Use Connect RPC mutation for revoke
  const revokeMutation = useMutation(revokeCredential);

  const handleRevoke = async (principalId: string, name: string) => {
    if (
      !confirm(
        `Revoke credential "${name}"?\n\nThis action cannot be undone. The credential will no longer be able to authenticate.`,
      )
    ) {
      return;
    }

    try {
      await revokeMutation.mutateAsync({ principalId });
      refetch(); // Refresh the list
    } catch (err) {
      alert(err instanceof Error ? err.message : "Failed to revoke credential");
    }
  };

  const credentials = data?.credentials || [];

  return (
    <div className="credentials-container">
      <ImportCredentialForm onSuccess={() => refetch()} />

      <div className="credentials-section">
        <h2 className="section-title">Credentials</h2>

        {isLoading && (
          <div className="events-loading">
            <div className="spinner"></div>
            <p>Loading credentials...</p>
          </div>
        )}

        {error && (
          <div className="events-error">
            <p>
              {error instanceof Error
                ? error.message
                : "Failed to load credentials"}
            </p>
            <button type="button" onClick={() => refetch()}>
              Retry
            </button>
          </div>
        )}

        {!isLoading && !error && credentials.length === 0 && (
          <div className="empty-state">
            <p>No credentials yet. Import one using the form above.</p>
          </div>
        )}

        {!isLoading && !error && credentials.length > 0 && (
          <CredentialsTable
            credentials={credentials}
            currentPrincipalId={user?.principal_id || ""}
            onRevoke={handleRevoke}
          />
        )}
      </div>
    </div>
  );
}

function Dashboard() {
  const { data } = useQuery(listJobs, {});
  const user = usePageContext();
  const [selectedJobId, setSelectedJobId] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"jobs" | "credentials">("jobs");

  // Hash routing: listen for URL hash changes
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash;
      if (hash === "#credentials") {
        setActiveTab("credentials");
        setSelectedJobId(null);
      } else if (hash.startsWith("#job-")) {
        setActiveTab("jobs");
        setSelectedJobId(hash.substring(5)); // Remove '#job-' prefix
      } else {
        setActiveTab("jobs");
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
          <nav className="topbar-tabs">
            <button
              type="button"
              className={activeTab === "jobs" ? "tab-active" : ""}
              onClick={() => {
                window.location.hash = "";
              }}
            >
              Jobs
            </button>
            <a
              href="#credentials"
              className={activeTab === "credentials" ? "tab-active" : ""}
            >
              Credentials
            </a>
          </nav>
        </div>
        <div className="topbar-right">
          <span className="user-name">{user?.name || "User"}</span>
          <a href="/logout" className="btn-logout">
            Logout
          </a>
        </div>
      </div>

      {/* Conditional rendering: show event view, credentials view, or job list */}
      {selectedJobId ? (
        <JobEventsView jobId={selectedJobId} />
      ) : activeTab === "credentials" ? (
        <CredentialsView />
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
                          <code>{job.jobId?.slice(-8)}</code>
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

// App wrapper that provides authenticated transport using session cookies
function AppWithToken() {
  // Create transport with session cookie authentication
  const transport = useMemo(
    () =>
      createConnectTransport({
        baseUrl: window.location.origin,
        credentials: "include", // Send session cookie with all requests
      }),
    [],
  );

  return (
    <TransportProvider transport={transport}>
      <QueryClientProvider client={queryClient}>
        <Dashboard />
      </QueryClientProvider>
    </TransportProvider>
  );
}

// Initialize on load
const appElement = document.getElementById("app");
if (!appElement) throw new Error("App element not found");
const root = createRoot(appElement);
root.render(<AppWithToken />);
