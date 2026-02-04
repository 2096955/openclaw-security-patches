# Prompt construction trust boundaries

This document lists all places where text is inserted into the system or user prompt, so injection defenses stay consistent. For each, we note whether the source is **trusted** or **untrusted** and whether content is **wrapped** (e.g. with [wrapExternalContent](/security/external-content)) or **raw**.

## System / user prompt injection points

| Location | Source | Wrapped? | Notes |
|----------|--------|----------|--------|
| **System prompt builder** | `src/agents/system-prompt.ts` | — | Server-controlled; extra parts may include API/system/developer content (see OpenResponses). |
| **Context files** | `src/agents/system-prompt.ts` (contextFiles) | **Yes (17)** | Wrapped with `wrapExternalContent` (source `api`) unless `file.trusted === true`; trusted means operator-controlled only. |
| **Subagent prompt** | `src/agents/subagent-announce.ts` (params.task) | **Documented (18)** | Task set by main agent/caller; only as trusted as main agent. Optional: detectSuspiciousPatterns + wrap. |
| **OpenResponses / OpenAI buildAgentPrompt** | `src/gateway/openresponses-http.ts`, OpenAI-compat | **Yes (16)** | Client-supplied `role: "system"` or `"developer"` wrapped with `wrapExternalContent` (source `api`) before adding to systemParts. |
| **Cron commandBody** | `src/cron/isolated-agent/run.ts` | Yes | Hook body wrapped; detectSuspiciousPatterns logged. |
| **Tool results** | Agent runners (OpenResponses, OpenAI, WS message handler) | **Audit (20)** | web_fetch wraps; other tools (file read, APIs) must wrap untrusted output before appending to conversation. |
| **extraSystemPrompt** | Various (agent request, config) | — | When from API/user, treat as untrusted and wrap. |

## Consistency checklist

- Every path that injects **external** content (hooks, web fetch, email, API-supplied system/developer, context files) should either wrap with `wrapExternalContent` or pass through `detectSuspiciousPatterns` and log when patterns are found.
- Tools that return string content to the model: ensure content from network, user files, or third-party APIs is wrapped before adding to the prompt or tool-result message.

## Tool output audit (item 20)

Tools that return string content to the model should wrap untrusted output with `wrapExternalContent` before it is appended to the conversation. Currently:

- **web_fetch** – wraps output (see `src/agents/tools/web-fetch.ts`).
- **File read / other tools** – audit and wrap when content is from network, user files, or third-party APIs.

At the orchestration layer, tools can be marked "untrusted" so their output is always wrapped even if the tool does not wrap.

## Two-phase / tool gating (item 21)

For high-risk sessions (elevated tools enabled), an optional config flag (e.g. `tools.elevated.requireCleanInput`) can run `detectSuspiciousPatterns` on the user message before the main agent run; if patterns are found, either wrap the message or restrict the tool set for that request. Placeholder: not yet implemented; see security audit plan item 21.

## Related

- [External content](/security/external-content) – `wrapExternalContent`, `detectSuspiciousPatterns`, `sanitizeUnicodeForSecurity`.
- Security audit plan: items 16–22 (API system/developer, context files, subagent task, suspicious patterns, tool output, two-phase gating, this doc).
