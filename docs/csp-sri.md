# Content Security Policy and Subresource Integrity (scaffold)

**Plan items K and L.** Control UI and web UIs can be hardened with CSP and SRI.

## K. Content Security Policy (CSP)

**Location:** Control UI HTTP responses (e.g. `src/gateway/control-ui.ts`), provider-web if applicable.

**Intended design:**

- Add strict CSP header to prevent XSS, e.g.:
  - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' wss:`
- Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`.

## L. Subresource Integrity (SRI)

**Location:** Any client-side assets served or referenced (script/link tags for external resources).

**Intended design:**

- Add `integrity` attributes to `<script>` and `<link>` tags for external resources.

## Status

- **CSP (K):** Implemented. Control UI HTML responses set `Content-Security-Policy` in `src/gateway/control-ui.ts` via `CONTROL_UI_CSP`; applied in `serveIndexHtml`. Unit tests in `control-ui.test.ts` assert the policy contains required directives and does not allow `default-src *` or unsafe script.
- **SRI (L):** Not yet applied. Add `integrity` attributes to `<script>` and `<link>` tags for external resources when control UI or provider-web references external assets.
