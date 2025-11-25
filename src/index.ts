import crypto from "node:crypto";
import type { NextFunction, Request, Response } from "express";

const PBKDF2_ITERATIONS = 1000;
const PBKDF2_KEY_LENGTH = 20;
const PBKDF2_ALGORITHM = "sha256";
const TOKEN_BYTE_LENGTH = 16;

export function validateAuthToken(
  token: string,
  expectedHash: string,
): boolean {
  const parts = token.split(".");
  if (parts.length !== 2) {
    return false;
  }

  const tokenHex = parts[0];
  const saltHex = parts[1];

  if (tokenHex.length === 0 || saltHex.length === 0) {
    return false;
  }

  // Pass hex strings as ASCII bytes (matching moosestack behavior)
  const derivedKey = crypto.pbkdf2Sync(
    tokenHex,
    saltHex,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    PBKDF2_ALGORITHM,
  );

  let expectedBytes: Buffer;
  try {
    expectedBytes = Buffer.from(expectedHash, "hex");
  } catch {
    return false;
  }

  if (expectedBytes.length !== PBKDF2_KEY_LENGTH) {
    return false;
  }

  return crypto.timingSafeEqual(derivedKey, expectedBytes);
}

export function createAuthMiddleware(
  getExpectedHash: (req: Request) => string | null,
) {
  return function authMiddleware(
    req: Request,
    res: Response,
    next: NextFunction,
  ): void {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res
        .status(401)
        .json({ error: "Missing or invalid Authorization header" });
      return;
    }

    const token = authHeader.slice(7);
    const expectedHash = getExpectedHash(req);

    if (!expectedHash) {
      res.status(401).json({ error: "No API key configured" });
      return;
    }

    if (!validateAuthToken(token, expectedHash)) {
      res.status(401).json({ error: "Invalid API key" });
      return;
    }

    next();
  };
}

export function generateApiKey(): { bearerToken: string; apiKeyHash: string } {
  const token = crypto.randomBytes(TOKEN_BYTE_LENGTH);
  const salt = crypto.randomBytes(TOKEN_BYTE_LENGTH);

  const tokenHex = token.toString("hex");
  const saltHex = salt.toString("hex");

  // Pass hex strings as ASCII bytes (matching moosestack behavior)
  const derivedKey = crypto.pbkdf2Sync(
    tokenHex,
    saltHex,
    PBKDF2_ITERATIONS,
    PBKDF2_KEY_LENGTH,
    PBKDF2_ALGORITHM,
  );

  return {
    bearerToken: `${tokenHex}.${saltHex}`,
    apiKeyHash: derivedKey.toString("hex"),
  };
}
