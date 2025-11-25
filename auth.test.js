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

describe('validateAuthToken edge cases', () => {
  const { validateAuthToken } = require('./auth');

  it('returns false for token without separator', () => {
    assert.strictEqual(validateAuthToken('abcd1234', 'aabbccdd'), false);
  });

  it('returns false for token with multiple separators', () => {
    assert.strictEqual(validateAuthToken('aa.bb.cc', 'aabbccdd'), false);
  });

  it('returns false for invalid hex in token', () => {
    assert.strictEqual(validateAuthToken('zzzz.1234', 'aabbccdd'), false);
  });

  it('returns false for invalid hex in salt', () => {
    assert.strictEqual(validateAuthToken('1234.zzzz', 'aabbccdd'), false);
  });

  it('returns false for invalid hex in expected hash', () => {
    assert.strictEqual(validateAuthToken('1234.5678', 'zzzzzzzz'), false);
  });

  it('returns false for wrong hash', () => {
    const { token } = generateTestToken();
    const wrongHash = 'a'.repeat(64);
    assert.strictEqual(validateAuthToken(token, wrongHash), false);
  });

  it('returns false for empty token part', () => {
    assert.strictEqual(validateAuthToken('.1234', 'a'.repeat(64)), false);
  });

  it('returns false for empty salt part', () => {
    assert.strictEqual(validateAuthToken('1234.', 'a'.repeat(64)), false);
  });
});

describe('createAuthMiddleware', () => {
  it('calls next() for valid Authorization header', async () => {
    const { createAuthMiddleware } = require('./auth');
    const { token, expectedHash } = generateTestToken();
    
    const getExpectedHash = () => expectedHash;
    const middleware = createAuthMiddleware(getExpectedHash);
    
    const req = { headers: { authorization: `Bearer ${token}` } };
    const res = {};
    let nextCalled = false;
    const next = () => { nextCalled = true; };
    
    middleware(req, res, next);
    
    assert.strictEqual(nextCalled, true);
  });
});
