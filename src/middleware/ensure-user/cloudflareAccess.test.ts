import { beforeEach, describe, expect, it, vi } from "vitest";
import { AppError } from "@/server/lib/errors";

const { mockEnv, jwtVerifyMock, resolveSharedWorkspaceContextMock } =
  vi.hoisted(() => ({
    mockEnv: {} as Record<string, string | undefined>,
    jwtVerifyMock: vi.fn(),
    resolveSharedWorkspaceContextMock: vi.fn(),
  }));

vi.mock("cloudflare:workers", () => ({
  env: mockEnv,
}));

vi.mock("jose", () => ({
  createRemoteJWKSet: vi.fn(() => "mock-jwks"),
  jwtVerify: (...args: unknown[]) => jwtVerifyMock(...args),
  errors: {
    JWTExpired: class JWTExpired extends Error {},
    JWTClaimValidationFailed: class JWTClaimValidationFailed extends Error {
      claim = "";
    },
    JWKSNoMatchingKey: class JWKSNoMatchingKey extends Error {},
    JWKSInvalid: class JWKSInvalid extends Error {},
    JWKSTimeout: class JWKSTimeout extends Error {},
    JOSEError: class JOSEError extends Error {
      static code = "ERR_JOSE_GENERIC";
      code = "ERR_JOSE_GENERIC";
    },
  },
}));

vi.mock("./delegated", () => ({
  resolveSharedWorkspaceContext: (...args: unknown[]) =>
    resolveSharedWorkspaceContextMock(...args),
}));

import { resolveCloudflareAccessContext } from "./cloudflareAccess";

describe("resolveCloudflareAccessContext", () => {
  beforeEach(() => {
    mockEnv.TEAM_DOMAIN = "https://jakehower.cloudflareaccess.com";
    mockEnv.POLICY_AUD = "aud-123";
    mockEnv.SERVICE_TOKEN_CLIENT_IDS =
      "6e21aa2d5f0a170c0d0ee9d3872e46cf.access";
    jwtVerifyMock.mockReset();
    resolveSharedWorkspaceContextMock.mockReset();
  });

  it("authenticates normal human Access JWTs via sub and email", async () => {
    jwtVerifyMock.mockResolvedValue({
      payload: { sub: "user-1", email: "jake@niftrip.com" },
    });
    resolveSharedWorkspaceContextMock.mockResolvedValue({
      userId: "user-1",
      userEmail: "jake@niftrip.com",
      emailVerified: true,
      organizationId: "shared-workspace",
      role: "owner",
    });

    const headers = new Headers({ "cf-access-jwt-assertion": "jwt-token" });
    const ctx = await resolveCloudflareAccessContext(headers);

    expect(resolveSharedWorkspaceContextMock).toHaveBeenCalledWith(
      "user-1",
      "jake@niftrip.com",
    );
    expect(ctx.userId).toBe("user-1");
  });

  it("authenticates allowlisted Cloudflare Access service tokens via common_name", async () => {
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: "",
        common_name: "6e21aa2d5f0a170c0d0ee9d3872e46cf.access",
      },
    });
    resolveSharedWorkspaceContextMock.mockResolvedValue({
      userId: "svc-6e21aa2d5f0a170c0d0ee9d3872e46cf",
      userEmail: "svc-6e21aa2d5f0a170c0d0ee9d3872e46cf@service.invalid",
      emailVerified: true,
      organizationId: "shared-workspace",
      role: "owner",
    });

    const headers = new Headers({ "cf-access-jwt-assertion": "svc-jwt" });
    const ctx = await resolveCloudflareAccessContext(headers);

    expect(resolveSharedWorkspaceContextMock).toHaveBeenCalledWith(
      "svc-6e21aa2d5f0a170c0d0ee9d3872e46cf",
      "svc-6e21aa2d5f0a170c0d0ee9d3872e46cf@service.invalid",
    );
    expect(ctx.userId).toBe("svc-6e21aa2d5f0a170c0d0ee9d3872e46cf");
  });

  it("rejects service tokens that are not in SERVICE_TOKEN_CLIENT_IDS", async () => {
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: "",
        common_name: "ffffffffffffffffffffffffffffffff.access",
      },
    });

    const headers = new Headers({ "cf-access-jwt-assertion": "svc-jwt" });
    await expect(resolveCloudflareAccessContext(headers)).rejects.toMatchObject(
      new AppError("UNAUTHENTICATED"),
    );
    expect(resolveSharedWorkspaceContextMock).not.toHaveBeenCalled();
  });

  it("rejects service tokens when SERVICE_TOKEN_CLIENT_IDS is unset", async () => {
    mockEnv.SERVICE_TOKEN_CLIENT_IDS = undefined;
    jwtVerifyMock.mockResolvedValue({
      payload: {
        sub: "",
        common_name: "6e21aa2d5f0a170c0d0ee9d3872e46cf.access",
      },
    });

    const headers = new Headers({ "cf-access-jwt-assertion": "svc-jwt" });
    await expect(resolveCloudflareAccessContext(headers)).rejects.toMatchObject(
      new AppError("UNAUTHENTICATED"),
    );
  });
});
