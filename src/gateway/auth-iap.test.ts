import {
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  SignJWT,
  type KeyLike,
} from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  validateIapJwt,
  validateServiceAccountToken,
  type IapIdentity,
  type ServiceAccountIdentity,
} from "./auth-iap.js";

/** Issuer used by auth-iap; duplicated here for test payloads. */
const IAP_ISSUER = "https://cloud.google.com/iap";
const SA_ISSUER = "https://accounts.google.com";

const TEST_KID = "test-kid";

/** RS256 key pair and JWKS for signing/verifying test JWTs (no network). */
let testPrivateKey: KeyLike;
let testJwks: ReturnType<typeof createLocalJWKSet>;

async function setupTestKeys() {
  const { publicKey, privateKey } = await generateKeyPair("RS256", {
    modulusLength: 2048,
    crv: "RS256",
  });
  testPrivateKey = privateKey;
  const jwk = await exportJWK(publicKey);
  jwk.alg = "RS256";
  jwk.use = "sig";
  jwk.kid = TEST_KID;
  testJwks = createLocalJWKSet({ keys: [jwk] });
}

/** Sign an IAP-style JWT (issuer, optional audience, email, sub, exp, hd). */
async function signIapJwt(payload: {
  issuer?: string;
  audience?: string;
  email?: string;
  sub?: string;
  hd?: string;
  exp?: number;
  iat?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    email: payload.email ?? "user@example.com",
    sub: payload.sub ?? "user-id-123",
    ...(payload.hd != null && { hd: payload.hd }),
  } as Record<string, unknown>)
    .setProtectedHeader({ alg: "RS256", kid: TEST_KID })
    .setIssuer(payload.issuer ?? IAP_ISSUER)
    .setAudience(payload.audience ?? "/projects/123/global/backendServices/456")
    .setExpirationTime(payload.exp ?? now + 3600)
    .setIssuedAt(payload.iat ?? now - 60)
    .sign(testPrivateKey);
}

/** Sign a service-account-style JWT (issuer, optional audience, email, exp). */
async function signSaJwt(payload: {
  issuer?: string;
  audience?: string;
  email?: string;
  project_id?: string;
  exp?: number;
  iat?: number;
}): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = {
    email: payload.email ?? `sa@project.iam.gserviceaccount.com`,
    ...(payload.project_id != null && { project_id: payload.project_id }),
  };
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "RS256", kid: TEST_KID })
    .setIssuer(payload.issuer ?? SA_ISSUER)
    .setAudience(payload.audience ?? "https://my-service")
    .setExpirationTime(payload.exp ?? now + 3600)
    .setIssuedAt(payload.iat ?? now - 60)
    .sign(testPrivateKey);
}

describe("validateIapJwt", () => {
  it("returns null for empty or missing token", async () => {
    expect(await validateIapJwt("")).toBeNull();
    expect(await validateIapJwt("   ")).toBeNull();
  });

  it("returns null for invalid JWT", async () => {
    expect(await validateIapJwt("not-a-jwt")).toBeNull();
    expect(await validateIapJwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.x")).toBeNull();
  });

  it("accepts optional audience", async () => {
    const bad = "invalid";
    expect(await validateIapJwt(bad, undefined)).toBeNull();
    expect(await validateIapJwt(bad, "/projects/123/global/backendServices/456")).toBeNull();
  });

  describe("with mocked JWKs (no network)", () => {
    beforeAll(setupTestKeys);

    it("returns identity for valid IAP JWT when audience matches", async () => {
      const audience = "/projects/99/global/backendServices/88";
      const token = await signIapJwt({
        audience,
        email: "alice@example.com",
        sub: "alice-id",
        hd: "example.com",
      });
      const result = await validateIapJwt(token, audience, { jwks: testJwks });
      expect(result).not.toBeNull();
      expect((result as IapIdentity).email).toBe("alice@example.com");
      expect((result as IapIdentity).userId).toBe("alice-id");
      expect((result as IapIdentity).hd).toBe("example.com");
    });

    it("returns identity for valid IAP JWT when audience not required", async () => {
      const token = await signIapJwt({ email: "bob@example.com", sub: "bob-id" });
      const result = await validateIapJwt(token, undefined, { jwks: testJwks });
      expect(result).not.toBeNull();
      expect((result as IapIdentity).email).toBe("bob@example.com");
      expect((result as IapIdentity).userId).toBe("bob-id");
    });

    it("returns null when audience does not match", async () => {
      const token = await signIapJwt({
        audience: "/projects/1/global/backendServices/1",
        email: "u@example.com",
        sub: "u",
      });
      const result = await validateIapJwt(
        token,
        "/projects/2/global/backendServices/2",
        { jwks: testJwks },
      );
      expect(result).toBeNull();
    });

    it("returns null for expired IAP JWT", async () => {
      const token = await signIapJwt({
        exp: Math.floor(Date.now() / 1000) - 3600,
        email: "e@example.com",
        sub: "e",
      });
      const result = await validateIapJwt(token, undefined, { jwks: testJwks });
      expect(result).toBeNull();
    });

    it("returns null when JWT signed with different key (invalid signature)", async () => {
      const { publicKey, privateKey } = await generateKeyPair("RS256", {
        modulusLength: 2048,
      });
      const otherJwk = await exportJWK(publicKey);
      otherJwk.alg = "RS256";
      otherJwk.use = "sig";
      otherJwk.kid = "other-kid";
      const otherJwks = createLocalJWKSet({ keys: [otherJwk] });
      const token = await new SignJWT({ email: "x@example.com", sub: "x" } as Record<string, unknown>)
        .setProtectedHeader({ alg: "RS256", kid: "other-kid" })
        .setIssuer(IAP_ISSUER)
        .setExpirationTime("1h")
        .setIssuedAt("1m ago")
        .sign(privateKey);
      const result = await validateIapJwt(token, undefined, { jwks: otherJwks });
      expect(result).not.toBeNull();
      const wrongJwks = testJwks;
      const resultWrong = await validateIapJwt(token, undefined, { jwks: wrongJwks });
      expect(resultWrong).toBeNull();
    });

    it("calls onValidationFailure when validation fails", async () => {
      const token = await signIapJwt({
        exp: Math.floor(Date.now() / 1000) - 1000,
        email: "x@example.com",
        sub: "x",
      });
      const failures: unknown[] = [];
      const result = await validateIapJwt(token, undefined, {
        jwks: testJwks,
        onValidationFailure: (err) => failures.push(err),
      });
      expect(result).toBeNull();
      expect(failures.length).toBe(1);
    });
  });
});

describe("validateServiceAccountToken", () => {
  it("returns null for empty or missing token", async () => {
    expect(await validateServiceAccountToken("")).toBeNull();
    expect(await validateServiceAccountToken("   ")).toBeNull();
  });

  it("returns null for invalid JWT", async () => {
    expect(await validateServiceAccountToken("not-a-jwt")).toBeNull();
  });

  it("accepts optional audience", async () => {
    expect(await validateServiceAccountToken("invalid", undefined)).toBeNull();
    expect(await validateServiceAccountToken("invalid", "https://my-service")).toBeNull();
  });

  describe("with mocked JWKs (no network)", () => {
    beforeAll(setupTestKeys);

    it("returns identity for valid service account JWT (.iam.gserviceaccount.com)", async () => {
      const audience = "https://my-backend";
      const email = "gateway@my-project.iam.gserviceaccount.com";
      const token = await signSaJwt({ audience, email, project_id: "my-project" });
      const result = await validateServiceAccountToken(token, audience, { jwks: testJwks });
      expect(result).not.toBeNull();
      expect((result as ServiceAccountIdentity).email).toBe(email);
      expect((result as ServiceAccountIdentity).projectId).toBe("my-project");
    });

    it("returns null when email is not a service account", async () => {
      const token = await signSaJwt({
        email: "user@gmail.com",
        audience: "https://api",
      });
      const result = await validateServiceAccountToken(token, "https://api", { jwks: testJwks });
      expect(result).toBeNull();
    });

    it("returns null when email does not end with .iam.gserviceaccount.com", async () => {
      const tokenEvil = await signSaJwt({
        email: "attacker@gserviceaccount.com.evil.com",
        audience: "https://api",
      });
      expect(await validateServiceAccountToken(tokenEvil, "https://api", { jwks: testJwks })).toBeNull();
      const tokenNotIam = await signSaJwt({
        email: "attacker@notgserviceaccount.com",
        audience: "https://api",
      });
      expect(await validateServiceAccountToken(tokenNotIam, "https://api", { jwks: testJwks })).toBeNull();
    });

    it("returns null for old suffix @project.gserviceaccount.com (without .iam.)", async () => {
      const token = await signSaJwt({
        email: "sa@project.gserviceaccount.com",
        audience: "https://api",
      });
      expect(await validateServiceAccountToken(token, "https://api", { jwks: testJwks })).toBeNull();
    });

    it("accepts service account email case-insensitively", async () => {
      const token = await signSaJwt({
        email: "SA@PROJECT.IAM.GSERVICEACCOUNT.COM",
        audience: "https://api",
      });
      const result = await validateServiceAccountToken(token, "https://api", { jwks: testJwks });
      expect(result).not.toBeNull();
      expect((result as ServiceAccountIdentity).email).toBe("SA@PROJECT.IAM.GSERVICEACCOUNT.COM");
    });

    it("returns null when email is null or empty", async () => {
      const now = Math.floor(Date.now() / 1000);
      const tokenEmpty = await new SignJWT({ email: "" } as Record<string, unknown>)
        .setProtectedHeader({ alg: "RS256", kid: TEST_KID })
        .setIssuer(SA_ISSUER)
        .setAudience("https://api")
        .setExpirationTime(now + 3600)
        .setIssuedAt(now - 60)
        .sign(testPrivateKey);
      expect(await validateServiceAccountToken(tokenEmpty, "https://api", { jwks: testJwks })).toBeNull();
      const tokenNoEmail = await new SignJWT({} as Record<string, unknown>)
        .setProtectedHeader({ alg: "RS256", kid: TEST_KID })
        .setIssuer(SA_ISSUER)
        .setAudience("https://api")
        .setExpirationTime(now + 3600)
        .setIssuedAt(now - 60)
        .sign(testPrivateKey);
      expect(await validateServiceAccountToken(tokenNoEmail, "https://api", { jwks: testJwks })).toBeNull();
    });

    it("returns null for expired service account JWT", async () => {
      const token = await signSaJwt({
        email: "sa@proj.iam.gserviceaccount.com",
        exp: Math.floor(Date.now() / 1000) - 3600,
      });
      const result = await validateServiceAccountToken(token, undefined, { jwks: testJwks });
      expect(result).toBeNull();
    });

    it("returns null when audience does not match", async () => {
      const token = await signSaJwt({
        audience: "https://service-a.com",
        email: "sa@proj.iam.gserviceaccount.com",
      });
      const result = await validateServiceAccountToken(token, "https://service-b.com", {
        jwks: testJwks,
      });
      expect(result).toBeNull();
    });

    it("returns null when issuer is wrong (e.g. user OAuth token)", async () => {
      const now = Math.floor(Date.now() / 1000);
      const wrongIssuerToken = await new SignJWT({
        email: "user@gmail.com",
      } as Record<string, unknown>)
        .setProtectedHeader({ alg: "RS256", kid: TEST_KID })
        .setIssuer("https://other.issuer.com")
        .setExpirationTime(now + 3600)
        .setIssuedAt(now - 60)
        .sign(testPrivateKey);
      const result = await validateServiceAccountToken(wrongIssuerToken, undefined, {
        jwks: testJwks,
      });
      expect(result).toBeNull();
    });

    it("calls onValidationFailure when validation fails", async () => {
      const token = await signSaJwt({
        email: "sa@project.iam.gserviceaccount.com",
        exp: Math.floor(Date.now() / 1000) - 1000,
      });
      const failures: unknown[] = [];
      const result = await validateServiceAccountToken(token, undefined, {
        jwks: testJwks,
        onValidationFailure: (err) => failures.push(err),
      });
      expect(result).toBeNull();
      expect(failures.length).toBe(1);
    });
  });
});
