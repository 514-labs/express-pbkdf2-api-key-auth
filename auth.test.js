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

describe('createAuthMiddleware error handling', () => {
  const { createAuthMiddleware } = require('./auth');

  it('returns 401 when Authorization header is missing', () => {
    const middleware = createAuthMiddleware(() => 'somehash');
    
    const req = { headers: {} };
    let statusCode, responseBody;
    const res = {
      status(code) { statusCode = code; return this; },
      json(body) { responseBody = body; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };
    
    middleware(req, res, next);
    
    assert.strictEqual(statusCode, 401);
    assert.strictEqual(responseBody.error, 'Missing or invalid Authorization header');
    assert.strictEqual(nextCalled, false);
  });

  it('returns 401 when Authorization header has wrong scheme', () => {
    const middleware = createAuthMiddleware(() => 'somehash');
    
    const req = { headers: { authorization: 'Basic abc123' } };
    let statusCode, responseBody;
    const res = {
      status(code) { statusCode = code; return this; },
      json(body) { responseBody = body; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };
    
    middleware(req, res, next);
    
    assert.strictEqual(statusCode, 401);
    assert.strictEqual(nextCalled, false);
  });

  it('returns 401 when getExpectedHash returns null', () => {
    const middleware = createAuthMiddleware(() => null);
    
    const req = { headers: { authorization: 'Bearer abc.def' } };
    let statusCode, responseBody;
    const res = {
      status(code) { statusCode = code; return this; },
      json(body) { responseBody = body; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };
    
    middleware(req, res, next);
    
    assert.strictEqual(statusCode, 401);
    assert.strictEqual(responseBody.error, 'No API key configured');
    assert.strictEqual(nextCalled, false);
  });

  it('returns 401 when token is invalid', () => {
    const { token, expectedHash } = generateTestToken();
    const middleware = createAuthMiddleware(() => expectedHash);
    
    const req = { headers: { authorization: 'Bearer wrong.token' } };
    let statusCode, responseBody;
    const res = {
      status(code) { statusCode = code; return this; },
      json(body) { responseBody = body; }
    };
    let nextCalled = false;
    const next = () => { nextCalled = true; };
    
    middleware(req, res, next);
    
    assert.strictEqual(statusCode, 401);
    assert.strictEqual(responseBody.error, 'Invalid API key');
    assert.strictEqual(nextCalled, false);
  });
});
