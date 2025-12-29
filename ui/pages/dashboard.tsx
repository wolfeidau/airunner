import { createRoot } from "react-dom/client";
import { createConnectTransport } from "@connectrpc/connect-web";
import { TransportProvider, useQuery } from "@connectrpc/connect-query";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { listJobs } from "../../api/gen/proto/es/job/v1/job-JobService_connectquery";
import { usePageContext } from "../lib/context";
import "./app.css";

function Index() {
  const { data } = useQuery(listJobs, {});
  const user = usePageContext();
  return <div>Index: Hello, {user?.name}! {data?.jobs?.map(job => job.jobId).join(", ")}</div>;
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
