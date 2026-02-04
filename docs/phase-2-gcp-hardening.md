# Phase 2: Enterprise GCP Hardening (scaffold)

To deploy OpenClaw on Google Cloud Platform (GCP) at an enterprise level (e.g. Cloud Run, GKE), the codebase needs to move beyond single-server assumptions. This page is a **scaffold** for the Phase 2 items; none are implemented yet.

---

## 10. Identity & Access (Beyond Tokens)

**Current:** Token/password auth handled by the app; IAP and Service Account auth implemented (Phase 2 build).

**Enterprise requirement:** Offload auth to infrastructure (Zero Trust).

**Implemented:**

- **IAP:** `src/gateway/auth-iap.ts` validates `X-Goog-IAP-JWT-Assertion` using Google's IAP JWKS. Config: `gateway.iap.enabled`, `gateway.iap.audience`.
- **Service Account OIDC:** Same module validates Bearer OIDC tokens (e.g. from Cloud Run). Config: `gateway.serviceAccount.enabled`, `gateway.serviceAccount.audience`.
- **Auth order:** IAP → Service Account → Tailscale → token/password. Resolved in `server-runtime-config.ts` and `cli/gateway-cli/run.ts`.

**Status:** Implemented. Tests: `src/gateway/auth-iap.test.ts`.

---

## 11. Structured Logging & Observability

**Current:** Generic JSON logging (`consoleStyle: "json"`).

**Enterprise requirement:** Fully structured logs that integrate with Cloud Logging (Stackdriver).

**Intended design:**

- Update logging formatter to output **GCP-compliant JSON**:
  - Map `level` to `severity` (INFO, WARNING, ERROR, CRITICAL).
  - Use `message` field instead of default key.
  - Include `logging.googleapis.com/trace` and `spanId` for distributed tracing (propagate from `X-Cloud-Trace-Context` header).
  - Include `httpRequest` object for access logs (latency, status, userAgent).

**Status:** Placeholder; not implemented.

---

## 12. Statelessness & Storage Abstraction

**Current:** Direct filesystem usage for sessions (`~/.openclaw/sessions`), media (`src/media/store.ts`), and device state.

**Enterprise requirement:** Stateless containers (Cloud Run/Kubernetes). Local disk is ephemeral.

**Intended design:**

- Abstract file I/O into a **Storage Provider** interface.
  - **Blob Storage:** Implement a GCS (Google Cloud Storage) adapter for media and session transcripts.
  - **State Store:** Move small state (device pairing, auth profiles) to a database (Cloud SQL/Firestore) or GCS blob, instead of local JSON files.
- Refactor `src/media/store.ts` and `src/config/sessions/store.ts` to use this abstraction.

**Status:** Placeholder; not implemented.

---

## 13. Sandbox Isolation (No Local Docker)

**Current:** `spawn("docker", ...)` assumes a local Docker daemon.

**Enterprise requirement:** Docker-in-Docker is insecure/difficult in managed environments.

**Intended design:**

- Abstract the execution environment (e.g. `src/agents/sandbox`).
  - Create a **Remote Sandbox** provider.
  - Options: **Cloud Build** (one-off builds), or **Sidecar/Remote API** (dedicated sandbox service via gRPC/HTTP).
- Ensure the "chat bash" feature can target this remote environment instead of the container's own shell.

**Status:** Placeholder; not implemented.

---

## 14. Secret Management

**Current:** Environment variables or `.env` files.

**Enterprise requirement:** Centralized secret rotation and auditing.

**Intended design:**

- **Native integration:** Add support for fetching configuration from **Google Secret Manager** at startup.
- **Mounting:** Document the pattern of mounting secrets as volumes (standard K8s/Cloud Run) and ensure the config loader prioritizes these file paths over env vars.

**Status:** Placeholder; not implemented.

---

## 15. Supply Chain Security

**Requirement:** Ensure code integrity.

**Intended design:**

- Generate **SBOMs** (Software Bill of Materials) during build.
- Sign container images (Cosign / Binary Authorization).
- Pin all dependencies (including transitive) in `package.json` / `pnpm-lock.yaml`.

**Status:** Placeholder; not implemented. Dependency audit is already in the release checklist (see [RELEASING](/reference/RELEASING)).
