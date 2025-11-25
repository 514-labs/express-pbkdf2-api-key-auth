const { describe, it } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

// Helper to generate a valid token and its expected hash
function generateTestToken() {
  const tokenBytes = crypto.randomBytes(16);
  const saltBytes = crypto.randomBytes(16);
  
  const derivedKey = crypto.pbkdf2Sync(tokenBytes, saltBytes, 1000, 32, 'sha256');
  
  return {
    token: `${tokenBytes.toString('hex')}.${saltBytes.toString('hex')}`,
    expectedHash: derivedKey.toString('hex')
  };
}

describe('validateAuthToken', () => {
  it('returns true for valid token matching expected hash', () => {
    const { validateAuthToken } = require('./auth');
    const { token, expectedHash } = generateTestToken();
    
    assert.strictEqual(validateAuthToken(token, expectedHash), true);
  });
});
