import crypto from "node:crypto";
import { expect } from "chai";
import type { NextFunction, Request, Response } from "express";
import {
  createAuthMiddleware,
  generateApiKey,
  validateAuthToken,
} from "../src/index";

// Generate token matching moosestack format: hex strings as ASCII bytes, 20-byte output
function generateTestToken() {
  const tokenHex = crypto.randomBytes(16).toString("hex");
  const saltHex = crypto.randomBytes(16).toString("hex");
  const derivedKey = crypto.pbkdf2Sync(tokenHex, saltHex, 1000, 20, "sha256");
  return {
    token: `${tokenHex}.${saltHex}`,
    expectedHash: derivedKey.toString("hex"),
  };
}

describe("validateAuthToken", () => {
  it("returns true for valid token matching expected hash", () => {
    const { token, expectedHash } = generateTestToken();
    expect(validateAuthToken(token, expectedHash)).to.equal(true);
  });
});

describe("validateAuthToken edge cases", () => {
  it("returns false for token without separator", () => {
    expect(validateAuthToken("abcd1234", "a".repeat(40))).to.equal(false);
  });

  it("returns false for token with multiple separators", () => {
    expect(validateAuthToken("aa.bb.cc", "a".repeat(40))).to.equal(false);
  });

  it("returns false for wrong hash", () => {
    const { token } = generateTestToken();
    const wrongHash = "a".repeat(40);
    expect(validateAuthToken(token, wrongHash)).to.equal(false);
  });

  it("returns false for empty token part", () => {
    expect(validateAuthToken(".1234", "a".repeat(40))).to.equal(false);
  });

  it("returns false for empty salt part", () => {
    expect(validateAuthToken("1234.", "a".repeat(40))).to.equal(false);
  });

  it("returns false for wrong length hash", () => {
    const { token } = generateTestToken();
    expect(validateAuthToken(token, "a".repeat(64))).to.equal(false);
  });
});

describe("generateApiKey", () => {
  it("generates a valid bearer token and hash", () => {
    const { bearerToken, apiKeyHash } = generateApiKey();

    expect(bearerToken).to.match(/^[a-f0-9]{32}\.[a-f0-9]{32}$/);
    expect(apiKeyHash).to.match(/^[a-f0-9]{40}$/);
    expect(validateAuthToken(bearerToken, apiKeyHash)).to.equal(true);
  });

  it("generates unique tokens each time", () => {
    const key1 = generateApiKey();
    const key2 = generateApiKey();

    expect(key1.bearerToken).to.not.equal(key2.bearerToken);
    expect(key1.apiKeyHash).to.not.equal(key2.apiKeyHash);
  });
});

describe("createAuthMiddleware", () => {
  it("calls next() for valid Authorization header", () => {
    const { token, expectedHash } = generateTestToken();
    const getExpectedHash = () => expectedHash;
    const middleware = createAuthMiddleware(getExpectedHash);

    const req = { headers: { authorization: `Bearer ${token}` } } as Request;
    const res = {} as Response;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as NextFunction;

    middleware(req, res, next);

    expect(nextCalled).to.equal(true);
  });
});

describe("createAuthMiddleware error handling", () => {
  it("returns 401 when Authorization header is missing", () => {
    const middleware = createAuthMiddleware(() => "a".repeat(40));

    const req = { headers: {} } as Request;
    let statusCode: number | undefined;
    let responseBody: { error: string } | undefined;
    const res = {
      status(code: number) {
        statusCode = code;
        return this;
      },
      json(body: { error: string }) {
        responseBody = body;
      },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal(
      "Missing or invalid Authorization header",
    );
    expect(nextCalled).to.equal(false);
  });

  it("returns 401 when Authorization header has wrong scheme", () => {
    const middleware = createAuthMiddleware(() => "a".repeat(40));

    const req = { headers: { authorization: "Basic abc123" } } as Request;
    let statusCode: number | undefined;
    const res = {
      status(code: number) {
        statusCode = code;
        return this;
      },
      json() {},
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(nextCalled).to.equal(false);
  });

  it("returns 401 when getExpectedHash returns null", () => {
    const middleware = createAuthMiddleware(() => null);

    const req = { headers: { authorization: "Bearer abc.def" } } as Request;
    let statusCode: number | undefined;
    let responseBody: { error: string } | undefined;
    const res = {
      status(code: number) {
        statusCode = code;
        return this;
      },
      json(body: { error: string }) {
        responseBody = body;
      },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal("No API key configured");
    expect(nextCalled).to.equal(false);
  });

  it("returns 401 when token is invalid", () => {
    const { expectedHash } = generateTestToken();
    const middleware = createAuthMiddleware(() => expectedHash);

    const req = {
      headers: { authorization: "Bearer wrong.token" },
    } as Request;
    let statusCode: number | undefined;
    let responseBody: { error: string } | undefined;
    const res = {
      status(code: number) {
        statusCode = code;
        return this;
      },
      json(body: { error: string }) {
        responseBody = body;
      },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => {
      nextCalled = true;
    }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal("Invalid API key");
    expect(nextCalled).to.equal(false);
  });
});
