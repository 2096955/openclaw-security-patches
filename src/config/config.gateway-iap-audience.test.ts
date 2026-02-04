import { describe, expect, it } from "vitest";
import { OpenClawSchema } from "./zod-schema.js";

describe("gateway.iap and gateway.serviceAccount audience required when enabled", () => {
  it("rejects gateway.iap.enabled true without audience", () => {
    const res = OpenClawSchema.safeParse({
      gateway: { iap: { enabled: true } },
    });
    expect(res.success).toBe(false);
    if (!res.success) {
      const iapIssue = res.error.issues.find(
        (iss) => iss.path.join(".") === "gateway.iap" && iss.message?.includes("audience"),
      );
      expect(iapIssue).toBeTruthy();
    }
  });

  it("rejects gateway.iap.enabled true with empty audience", () => {
    const res = OpenClawSchema.safeParse({
      gateway: { iap: { enabled: true, audience: "   " } },
    });
    expect(res.success).toBe(false);
    if (!res.success) {
      const iapIssue = res.error.issues.find(
        (iss) => iss.path.join(".") === "gateway.iap" && iss.message?.includes("audience"),
      );
      expect(iapIssue).toBeTruthy();
    }
  });

  it("accepts gateway.iap.enabled true with non-empty audience", () => {
    const res = OpenClawSchema.safeParse({
      gateway: { iap: { enabled: true, audience: "/projects/123/global/backendServices/456" } },
    });
    expect(res.success).toBe(true);
  });

  it("rejects gateway.serviceAccount.enabled true without audience", () => {
    const res = OpenClawSchema.safeParse({
      gateway: { serviceAccount: { enabled: true } },
    });
    expect(res.success).toBe(false);
    if (!res.success) {
      const saIssue = res.error.issues.find(
        (iss) =>
          iss.path.join(".") === "gateway.serviceAccount" && iss.message?.includes("audience"),
      );
      expect(saIssue).toBeTruthy();
    }
  });

  it("accepts gateway.serviceAccount.enabled true with non-empty audience", () => {
    const res = OpenClawSchema.safeParse({
      gateway: { serviceAccount: { enabled: true, audience: "https://my-service" } },
    });
    expect(res.success).toBe(true);
  });

  it("accepts gateway.iap and gateway.serviceAccount when disabled or omitted", () => {
    expect(OpenClawSchema.safeParse({ gateway: { iap: { enabled: false } } }).success).toBe(true);
    expect(OpenClawSchema.safeParse({ gateway: {} }).success).toBe(true);
  });
});
