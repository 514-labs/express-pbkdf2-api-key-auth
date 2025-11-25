# express-pbkdf2-api-key-auth

Express middleware for PBKDF2 API key authentication. Zero external dependencies (uses Node.js crypto).

## Installation

```bash
npm install @514-labs/express-pbkdf2-api-key-auth
```

## Usage

```javascript
import express from "express";
import { createAuthMiddleware } from "express-pbkdf2-api-key-auth";

const app = express();

const authMiddleware = createAuthMiddleware((req) => {
  // Return the expected hash for this request
  return process.env.API_KEY_HASH;
});

app.use(authMiddleware);

app.get("/api/protected", (req, res) => {
  res.json({ message: "Authenticated!" });
});

app.listen(3000);
```

## Token Format

Clients send tokens in the Authorization header:

```
Authorization: Bearer {token_hex}.{salt_hex}
```

The middleware validates the token using PBKDF2-HMAC-SHA256 with:

- 1000 iterations
- 32-byte output
- Constant-time comparison (timing-attack safe)

## API

### `createAuthMiddleware(getExpectedHash)`

Creates an Express middleware for authentication.

**Parameters:**

- `getExpectedHash(req)` - Function that returns the expected hash for the request, or `null` if no key is configured

**Returns:** Express middleware function

**Responses:**

- `401` - Missing/invalid Authorization header, no API key configured, or invalid token
- Calls `next()` on successful authentication
