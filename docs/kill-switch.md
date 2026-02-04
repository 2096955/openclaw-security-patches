# Kill switch and circuit breaker (scaffold)

**Plan item M.** No documented mechanism to rapidly disable a compromised channel, agent, or tool.

## Intended design

- Add `openclaw kill <channel|agent|tool>` for immediate disable.
- Support remote kill via control channel or API.
- Log all kill events with reason and operator.
- Optional: auto-kill on anomaly detection.

## Status

Placeholder; not implemented. See security audit plan item M.

**Code reference (when implementing):** CLI command under `src/commands/` (e.g. `openclaw kill <channel|agent|tool>`); gateway runtime in `src/gateway/server.ts` / `src/gateway/server-channels.ts` to apply disable; control channel or API to trigger remote kill.
