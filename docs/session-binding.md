# Session and token binding (scaffold)

**Plan item J.** Tokens/sessions are not currently bound to client characteristics; stolen tokens can be reused from any location.

## Intended design

- Optional IP binding or fingerprinting for high-security deployments.
- Token refresh with sliding expiration.
- Session invalidation on security-sensitive changes (e.g. password change).
- Log token usage patterns for anomaly detection.

## Status

Placeholder; not implemented. See security audit plan item J.

**Code reference (when implementing):** `authorizeGatewayConnect` in `src/gateway/auth.ts`; optional IP or fingerprint binding before returning `ok: true`. Session/store in `src/config/sessions/store.ts`.
