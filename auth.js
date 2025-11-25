const crypto = require('node:crypto');

function validateAuthToken(token, expectedHash) {
  const parts = token.split('.');
  if (parts.length !== 2) {
    return false;
  }

  let tokenBytes, saltBytes, expectedBytes;
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

function createAuthMiddleware(getExpectedHash) {
  return function authMiddleware(req, res, next) {
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

module.exports = { validateAuthToken, createAuthMiddleware };
