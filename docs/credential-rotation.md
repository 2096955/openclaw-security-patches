# Credential and token rotation (scaffold)

**Plan item F.** No documented mechanism yet for rotating gateway tokens, API keys, or channel credentials without downtime.

## Intended design

- Support multiple active tokens during rotation (accept old + new for a grace period).
- Add `openclaw credentials rotate` (or equivalent) with zero-downtime semantics.
- Document rotation procedures for each credential type (gateway auth, hooks token, channel tokens).
- For GCP: integrate with Secret Manager versioning.

## Status

Placeholder; not implemented. See security audit plan item F.

**Code reference (when implementing):** Gateway auth in `src/gateway/auth.ts` (`resolveGatewayAuth`, `authorizeGatewayConnect`); hooks token in `src/gateway/hooks.ts` and `src/gateway/server-http.ts`. Support multiple active tokens during rotation (e.g. accept old + new for a grace period).
