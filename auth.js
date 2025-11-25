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

module.exports = { validateAuthToken };
