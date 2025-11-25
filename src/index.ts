import crypto from 'node:crypto';
import type { Request, Response, NextFunction } from 'express';

export function validateAuthToken(token: string, expectedHash: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return false;
  }

  let tokenBytes: Buffer, saltBytes: Buffer, expectedBytes: Buffer;
  try {
    tokenBytes = Buffer.from(parts[0], 'hex');
    saltBytes = Buffer.from(parts[1], 'hex');
    expectedBytes = Buffer.from(expectedHash, 'hex');
  } catch {
    return false;
  }

  if (tokenBytes.length === 0 || saltBytes.length === 0 || expectedBytes.length === 0) {
    return false;
  }

  const derivedKey = crypto.pbkdf2Sync(tokenBytes, saltBytes, 1000, 32, 'sha256');

  return crypto.timingSafeEqual(derivedKey, expectedBytes);
}

export function createAuthMiddleware(getExpectedHash: (req: Request) => string | null) {
  return function authMiddleware(req: Request, res: Response, next: NextFunction): void {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'Missing or invalid Authorization header' });
      return;
    }

    const token = authHeader.slice(7);
    const expectedHash = getExpectedHash(req);

    if (!expectedHash) {
      res.status(401).json({ error: 'No API key configured' });
      return;
    }

    if (!validateAuthToken(token, expectedHash)) {
      res.status(401).json({ error: 'Invalid API key' });
      return;
    }

    next();
  };
}
