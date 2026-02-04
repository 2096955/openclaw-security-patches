/**
 * In-memory rate limiter for failed gateway auth attempts (brute-force mitigation).
 * Per client identifier (e.g. IP after proxy). In multi-instance deployments,
 * limits are per process unless a shared store is added later.
 */

const DEFAULT_MAX_FAILED_ATTEMPTS = 10;
const DEFAULT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

const failuresByClient = new Map<string, number[]>();

function prune(windowMs: number, timestamps: number[]): number[] {
  const cutoff = Date.now() - windowMs;
  return timestamps.filter((t) => t > cutoff);
}

export function checkAuthRateLimit(clientId: string): { allowed: boolean } {
  const key = clientId || "unknown";
  const list = failuresByClient.get(key);
  if (!list || list.length === 0) {
    return { allowed: true };
  }
  const pruned = prune(DEFAULT_WINDOW_MS, list);
  if (pruned.length >= DEFAULT_MAX_FAILED_ATTEMPTS) {
    return { allowed: false };
  }
  if (pruned.length !== list.length) {
    failuresByClient.set(key, pruned);
  }
  return { allowed: true };
}

export function recordAuthFailure(clientId: string): void {
  const key = clientId || "unknown";
  const list = prune(DEFAULT_WINDOW_MS, failuresByClient.get(key) ?? []);
  list.push(Date.now());
  failuresByClient.set(key, list);
}

/** On success, do not full-reset; keep sliding window so repeated failures still count until they expire. */
export function recordAuthSuccess(clientId: string): void {
  const key = clientId || "unknown";
  const list = failuresByClient.get(key);
  if (!list || list.length === 0) {
    return;
  }
  const pruned = prune(DEFAULT_WINDOW_MS, list);
  if (pruned.length > 0) {
    failuresByClient.set(key, pruned);
  } else {
    failuresByClient.delete(key);
  }
}
