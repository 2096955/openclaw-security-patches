/**
 * Phase 2 item 10: IAP (Identity-Aware Proxy) and Service Account OIDC validation.
 * Validates X-Goog-IAP-JWT-Assertion and Bearer OIDC tokens before falling back to token/password auth.
 */

import { createRemoteJWKSet, jwtVerify, type JWTPayload, type KeyLike } from "jose";
import { createSubsystemLogger } from "../logging/subsystem.js";

const IAP_JWKS_URL = "https://www.gstatic.com/iap/verify/public_key-jwk";
const IAP_ISSUER = "https://cloud.google.com/iap";
const GOOGLE_OAUTH2_JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
/** Service account OIDC tokens use this issuer; validates to reject user OAuth tokens. */
const SERVICE_ACCOUNT_ISSUER = "https://accounts.google.com";
/** Reject tokens that are not from a service account (e.g. Gmail OAuth). */
const SERVICE_ACCOUNT_EMAIL_SUFFIX = ".iam.gserviceaccount.com";

const logAuthIap = createSubsystemLogger("gateway");

/** Cached JWKS for IAP (1h TTL). On fetch failure we clear cache so next request retries. */
let iapJwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let iapJwksExpiry = 0;
const IAP_JWKS_TTL_MS = 60 * 60 * 1000;

function getIapJwks(): ReturnType<typeof createRemoteJWKSet> {
  const now = Date.now();
  if (!iapJwks || now > iapJwksExpiry) {
    try {
      iapJwks = createRemoteJWKSet(new URL(IAP_JWKS_URL));
      iapJwksExpiry = now + IAP_JWKS_TTL_MS;
    } catch (err) {
      logAuthIap.warn("IAP JWKS init failed; will retry on next request", { err: String(err) });
      if (iapJwks) {
        iapJwksExpiry = 0;
      }
      throw err;
    }
  }
  return iapJwks;
}

export type IapIdentity = {
  email: string;
  userId: string;
  hd?: string;
};

export type ValidateIapOptions = {
  /** For tests only: use this key/JWKS instead of remote IAP JWKS. */
  jwks?: KeyLike | ReturnType<typeof createRemoteJWKSet>;
  /** Called on validation failure for diagnostics. */
  onValidationFailure?: (err: unknown) => void;
};

/**
 * Validates IAP JWT from X-Goog-IAP-JWT-Assertion header.
 * Returns identity on success, null on invalid/expired/wrong audience.
 * When audience is required by config (gateway.iap.enabled), caller must pass audience.
 */
export async function validateIapJwt(
  token: string,
  audience?: string,
  options?: ValidateIapOptions,
): Promise<IapIdentity | null> {
  if (!token?.trim()) {
    return null;
  }
  const onFailure = options?.onValidationFailure;
  try {
    const jwks = options?.jwks ?? getIapJwks();
    const opts: { issuer: string; audience?: string } = { issuer: IAP_ISSUER };
    if (audience?.trim()) {
      opts.audience = audience.trim();
    }
    const result =
      typeof jwks === "function"
        ? await jwtVerify(token.trim(), jwks, opts)
        : await jwtVerify(token.trim(), jwks, opts);
    const payload = result.payload;
    const email = typeof payload.email === "string" ? payload.email : "";
    const userId = typeof payload.sub === "string" ? payload.sub : String(payload.sub ?? "");
    if (!email && !userId) {
      return null;
    }
    return {
      email,
      userId,
      hd: typeof payload.hd === "string" ? payload.hd : undefined,
    };
  } catch (err) {
    onFailure?.(err);
    logAuthIap.warn("IAP JWT validation failed", { err: String(err) });
    return null;
  }
}

/** Cached JWKS for Google OAuth2 (1h TTL). On fetch failure we clear cache so next request retries. */
let oauth2Jwks: ReturnType<typeof createRemoteJWKSet> | null = null;
let oauth2JwksExpiry = 0;

function getOauth2Jwks(): ReturnType<typeof createRemoteJWKSet> {
  const now = Date.now();
  if (!oauth2Jwks || now > oauth2JwksExpiry) {
    try {
      oauth2Jwks = createRemoteJWKSet(new URL(GOOGLE_OAUTH2_JWKS_URL));
      oauth2JwksExpiry = now + IAP_JWKS_TTL_MS;
    } catch (err) {
      logAuthIap.warn("OAuth2 JWKS init failed; will retry on next request", { err: String(err) });
      if (oauth2Jwks) {
        oauth2JwksExpiry = 0;
      }
      throw err;
    }
  }
  return oauth2Jwks;
}

export type ServiceAccountIdentity = {
  email: string;
  projectId?: string;
};

export type ValidateServiceAccountOptions = {
  /** For tests only: use this key/JWKS instead of remote OAuth2 JWKS. */
  jwks?: KeyLike | ReturnType<typeof createRemoteJWKSet>;
  /** Called on validation failure for diagnostics. */
  onValidationFailure?: (err: unknown) => void;
};

/**
 * Validates Google OIDC token from a service account (e.g. Cloud Run).
 * Requires issuer https://accounts.google.com and email ending in gserviceaccount.com
 * so that user OAuth tokens (Gmail, Calendar, etc.) are rejected.
 */
export async function validateServiceAccountToken(
  token: string,
  audience?: string,
  options?: ValidateServiceAccountOptions,
): Promise<ServiceAccountIdentity | null> {
  if (!token?.trim()) {
    return null;
  }
  const onFailure = options?.onValidationFailure;
  try {
    const jwks = options?.jwks ?? getOauth2Jwks();
    const opts: { issuer: string; audience?: string } = { issuer: SERVICE_ACCOUNT_ISSUER };
    if (audience?.trim()) {
      opts.audience = audience.trim();
    }
    const result =
      typeof jwks === "function"
        ? await jwtVerify(token.trim(), jwks, opts)
        : await jwtVerify(token.trim(), jwks, opts);
    const payload = result.payload;
    const email = typeof payload.email === "string" ? payload.email : "";
    if (!email) {
      return null;
    }
    if (!email.toLowerCase().endsWith(SERVICE_ACCOUNT_EMAIL_SUFFIX)) {
      logAuthIap.warn("Service account token rejected: email is not a service account", {
        email: email.slice(0, 20) + "...",
      });
      return null;
    }
    const googlePayload = payload as JWTPayload & { google?: { project_id?: string } };
    let projectId: string | undefined;
    if (typeof payload.project_id === "string") {
      projectId = payload.project_id;
    } else if (typeof googlePayload.google?.project_id === "string") {
      projectId = googlePayload.google.project_id;
    }
    return { email, projectId };
  } catch (err) {
    onFailure?.(err);
    logAuthIap.warn("Service account JWT validation failed", { err: String(err) });
    return null;
  }
}
