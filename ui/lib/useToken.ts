import { useState, useEffect, useCallback, useRef } from "react";
import { fetchToken, getRefreshTimeMs } from "./token";

/**
 * React hook for managing JWT token lifecycle.
 * Fetches token from /auth/token endpoint and handles auto-refresh.
 *
 * Returns:
 * - token: Current JWT token, or null if loading/error
 * - isLoading: True while initial token fetch is in progress
 * - error: Error message if token fetch failed
 * - refresh: Manual refresh function (useful for handling 401s)
 */
export function useToken() {
  const [token, setToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Track refresh timeout so we can cancel it on unmount
  const refreshTimeoutRef = useRef<number | null>(null);

  const doRefresh = useCallback(async () => {
    try {
      const tokenData = await fetchToken();

      setToken(tokenData.access_token);
      setError(null);

      // Schedule next refresh at 50% of token lifetime
      const refreshMs = getRefreshTimeMs(tokenData.expires_in);
      refreshTimeoutRef.current = window.setTimeout(() => {
        doRefresh();
      }, refreshMs);
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch token";
      setError(message);
      setToken(null);

      // Retry after 5 seconds on error
      refreshTimeoutRef.current = window.setTimeout(() => {
        doRefresh();
      }, 5000);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial fetch on mount
  useEffect(() => {
    doRefresh();

    // Cleanup: cancel refresh timeout on unmount
    return () => {
      if (refreshTimeoutRef.current) {
        clearTimeout(refreshTimeoutRef.current);
      }
    };
  }, [doRefresh]);

  return { token, isLoading, error, refresh: doRefresh };
}
