# Replay attack protection (scaffold)

**Plan item O.** Callback and webhook endpoints should reject replayed requests.

## Current state

- **Gateway hooks:** Optional replay protection via `checkHookReplayTimestamp()` (reject payloads with `timestamp`/`ts` older than 5 minutes). Callers can opt in by including a timestamp in the JSON body.
- **Platform webhooks:** Telegram (grammy secret token), Slack (Bolt signing secret), and LINE (signature validation) are verified by their libraries. Hooks replay window applies when timestamp is present.

## Intended design for other callbacks

- Include and validate timestamp in signed payloads; reject if older than 5 minutes.
- Optionally track nonces to prevent exact replay within the window.
- Log and alert on replay attempts.

## Status

Hooks replay scaffolding implemented; other callback endpoints to be audited. See security audit plan item O.
