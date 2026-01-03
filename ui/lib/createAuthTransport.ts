import { createConnectTransport } from "@connectrpc/connect-web";
import type { Transport } from "@connectrpc/connect";

/**
 * Create a Connect RPC transport that injects JWT token in Authorization header.
 * If token is null, requests proceed without Authorization header.
 */
export function createAuthTransport(
  baseUrl: string,
  token: string | null,
): Transport {
  return createConnectTransport({
    baseUrl,
    interceptors: [
      (next) => async (req) => {
        // Inject token if available
        if (token) {
          req.header.set("Authorization", `Bearer ${token}`);
        }
        return next(req);
      },
    ],
  });
}
