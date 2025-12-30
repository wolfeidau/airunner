import { createRoot } from "react-dom/client";
import { createConnectTransport } from "@connectrpc/connect-web";
import { TransportProvider } from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import "./app.css";

function Index() {
  return (
    <div className="shell-container">
      <div className="shell-content">
        <div className="header">
          <h1>airunner</h1>
          <p className="tagline">Job orchestration platform</p>
        </div>

        <div className="summary">
          <p>
            A Go-based job orchestration platform with production-ready AWS backend support.
            Submit, execute, and monitor long-running jobs with ease.
          </p>
        </div>

        <div className="actions">
          <a href="/login" className="btn btn-primary">
            <span className="github-icon">★</span>
            Login with GitHub
          </a>
        </div>

        <div className="footer-text">
          <p>Fast • Reliable • Observable</p>
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
      <Index />
    </QueryClientProvider>
  </TransportProvider>
);
