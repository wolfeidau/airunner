import { createRoot } from "react-dom/client";
import { createConnectTransport } from "@connectrpc/connect-web";
import { TransportProvider, useQuery } from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { listJobs } from "../../api/gen/proto/es/job/v1/job-JobService_connectquery";
import { usePageContext } from "../lib/context";
import { JobState } from "../../api/gen/proto/es/job/v1/job_pb";
import { timestampToJsDate } from "../lib/proto_convert";

import "./app.css";
import "./dashboard.css";

function Dashboard() {
  const { data } = useQuery(listJobs, {});
  const user = usePageContext();

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

  const formatDate = (timestamp: any): string => {
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

      {/* Main Content */}
      <div className="dashboard-content">
        {/* CLI Section */}
        <div className="cli-section">
          <div className="cli-header">
            <h2>Submit a Job</h2>
            <p className="cli-subtitle">Use the CLI to submit jobs to your queue</p>
          </div>
          <div className="cli-command">
            <code>$ airunner-cli submit --server=https://localhost:8993 --queue=default github.com/example/repo</code>
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
                    <tr key={job.jobId} className="job-row">
                      <td className="cell-job-id">
                        <code>{job.jobId?.slice(0, 8)}</code>
                      </td>
                      <td className="cell-repo">
                        {job.jobParams?.repository || "-"}
                      </td>
                      <td className="cell-date">{formatDate(job.createdAt)}</td>
                      <td className="cell-status">
                        <span className={`status-badge ${getStateColor(job.state)}`}>
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
    </div>
  );
}

const queryClient = new QueryClient();
const finalTransport = createConnectTransport({
  baseUrl: "https://localhost:8993",
});

// Initialize on load
const root = createRoot(document.getElementById("app")!);
root.render(
  <TransportProvider transport={finalTransport}>
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  </TransportProvider>
);
