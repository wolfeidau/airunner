/**
 * Token management for JWT authentication.
 * Handles fetching, caching, and refreshing JWT tokens from /auth/token endpoint.
 */

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: string;
}

/**
 * Fetch a new JWT token from the /auth/token endpoint.
 * Uses the session cookie automatically (credentials: 'include').
 */
export async function fetchToken(): Promise<TokenResponse> {
  const response = await fetch("/auth/token", {
    method: "POST",
    credentials: "include", // Send session cookie
    headers: {
      "Content-Type": "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(
      `Failed to fetch token: ${response.status} ${response.statusText}`,
    );
  }

  return response.json();
}

/**
 * Parse expiry time from token response.
 * Returns milliseconds until expiry.
 */
export function getTokenExpiryMs(expiresIn: string): number {
  const seconds = parseInt(expiresIn, 10);
  return seconds * 1000; // Convert to milliseconds
}

/**
 * Calculate when to refresh token (at 50% of expiry time).
 * This ensures we refresh while token is still valid.
 */
export function getRefreshTimeMs(expiresIn: string): number {
  return getTokenExpiryMs(expiresIn) * 0.5;
}
