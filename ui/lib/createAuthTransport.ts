import { createConnectTransport } from "@connectrpc/connect-web";
import type { Transport } from "@connectrpc/connect";

/**
 * Create a Connect RPC transport with session cookie support.
 * Uses credentials: 'include' to send session cookie automatically.
 * JWT token is optional - dual auth middleware supports both.
 */
export function createAuthTransport(
  baseUrl: string,
  token: string | null,
): Transport {
  return createConnectTransport({
    baseUrl,
    credentials: "include", // Send session cookie
    interceptors: [
      (next) => async (req) => {
        // Inject token if available (optional, session cookie works too)
        if (token) {
          req.header.set("Authorization", `Bearer ${token}`);
        }
        return next(req);
      },
    ],
  });
}
