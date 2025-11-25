import { expect } from "chai";
import crypto from "node:crypto";
import { validateAuthToken, createAuthMiddleware } from "../src/index";
import type { Request, Response, NextFunction } from "express";

function generateTestToken() {
  const tokenBytes = crypto.randomBytes(16);
  const saltBytes = crypto.randomBytes(16);
  const derivedKey = crypto.pbkdf2Sync(tokenBytes, saltBytes, 1000, 32, "sha256");
  return {
    token: `${tokenBytes.toString("hex")}.${saltBytes.toString("hex")}`,
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
    expect(validateAuthToken("abcd1234", "aabbccdd")).to.equal(false);
  });

  it("returns false for token with multiple separators", () => {
    expect(validateAuthToken("aa.bb.cc", "aabbccdd")).to.equal(false);
  });

  it("returns false for invalid hex in token", () => {
    expect(validateAuthToken("zzzz.1234", "aabbccdd")).to.equal(false);
  });

  it("returns false for invalid hex in salt", () => {
    expect(validateAuthToken("1234.zzzz", "aabbccdd")).to.equal(false);
  });

  it("returns false for invalid hex in expected hash", () => {
    expect(validateAuthToken("1234.5678", "zzzzzzzz")).to.equal(false);
  });

  it("returns false for wrong hash", () => {
    const { token } = generateTestToken();
    const wrongHash = "a".repeat(64);
    expect(validateAuthToken(token, wrongHash)).to.equal(false);
  });

  it("returns false for empty token part", () => {
    expect(validateAuthToken(".1234", "a".repeat(64))).to.equal(false);
  });

  it("returns false for empty salt part", () => {
    expect(validateAuthToken("1234.", "a".repeat(64))).to.equal(false);
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
    const next = (() => { nextCalled = true; }) as NextFunction;

    middleware(req, res, next);

    expect(nextCalled).to.equal(true);
  });
});

describe("createAuthMiddleware error handling", () => {
  it("returns 401 when Authorization header is missing", () => {
    const middleware = createAuthMiddleware(() => "somehash");

    const req = { headers: {} } as Request;
    let statusCode: number | undefined;
    let responseBody: { error: string } | undefined;
    const res = {
      status(code: number) { statusCode = code; return this; },
      json(body: { error: string }) { responseBody = body; },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => { nextCalled = true; }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal("Missing or invalid Authorization header");
    expect(nextCalled).to.equal(false);
  });

  it("returns 401 when Authorization header has wrong scheme", () => {
    const middleware = createAuthMiddleware(() => "somehash");

    const req = { headers: { authorization: "Basic abc123" } } as Request;
    let statusCode: number | undefined;
    const res = {
      status(code: number) { statusCode = code; return this; },
      json() {},
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => { nextCalled = true; }) as NextFunction;

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
      status(code: number) { statusCode = code; return this; },
      json(body: { error: string }) { responseBody = body; },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => { nextCalled = true; }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal("No API key configured");
    expect(nextCalled).to.equal(false);
  });

  it("returns 401 when token is invalid", () => {
    const { expectedHash } = generateTestToken();
    const middleware = createAuthMiddleware(() => expectedHash);

    const req = { headers: { authorization: "Bearer wrong.token" } } as Request;
    let statusCode: number | undefined;
    let responseBody: { error: string } | undefined;
    const res = {
      status(code: number) { statusCode = code; return this; },
      json(body: { error: string }) { responseBody = body; },
    } as unknown as Response;
    let nextCalled = false;
    const next = (() => { nextCalled = true; }) as NextFunction;

    middleware(req, res, next);

    expect(statusCode).to.equal(401);
    expect(responseBody?.error).to.equal("Invalid API key");
    expect(nextCalled).to.equal(false);
  });
});
