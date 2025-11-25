# express-pbkdf2-api-key-auth

Express middleware for PBKDF2 API key authentication. Zero external dependencies (uses Node.js crypto). Compatible with [moosestack](https://github.com/514-labs/moosestack) token format.

## Installation

```bash
npm install @514labs/express-pbkdf2-api-key-auth
```

## Generating API Keys

Use the CLI to generate an API key pair:

```bash
npx generate-api-key
```

Output:
```
API Key Hash (store server-side):
1ee1d40d1e14b3bacd42fc610f18edcce993f64b

Bearer Token (give to client):
3cb36f1346330dbd9b662487f0b70dad.1f6727c8bb1b2463a9c94a1ff8ea6f33
```

Or programmatically:

```javascript
import { generateApiKey } from "@514labs/express-pbkdf2-api-key-auth";

const { bearerToken, apiKeyHash } = generateApiKey();
// Store apiKeyHash server-side, give bearerToken to client
```

## Usage

```javascript
import express from "express";
import { createAuthMiddleware } from "@514labs/express-pbkdf2-api-key-auth";

const app = express();

const authMiddleware = createAuthMiddleware((req) => {
  // Return the expected hash for this request
  // Could look up per-user hash from database
  return process.env.API_KEY_HASH;
});

app.use("/api", authMiddleware);

app.get("/api/protected", (req, res) => {
  res.json({ message: "Authenticated!" });
});

app.listen(3000);
```

Clients authenticate with:

```
Authorization: Bearer {token_hex}.{salt_hex}
```

## Token Format

The token format is compatible with moosestack's `moose generate hash-token` command:

- Token: 16 random bytes (32-char hex string)
- Salt: 16 random bytes (32-char hex string)
- Hash: PBKDF2-HMAC-SHA256, 1000 iterations, 20-byte output
- Constant-time comparison (timing-attack safe)

## API

### `generateApiKey()`

Generates a new API key pair.

**Returns:** `{ bearerToken: string, apiKeyHash: string }`

### `createAuthMiddleware(getExpectedHash)`

Creates an Express middleware for authentication.

**Parameters:**
- `getExpectedHash(req)` - Function that returns the expected hash for the request, or `null` if no key is configured

**Returns:** Express middleware function

**Responses:**
- `401` - Missing/invalid Authorization header, no API key configured, or invalid token
- Calls `next()` on successful authentication

### `validateAuthToken(token, expectedHash)`

Low-level function to validate a token against an expected hash.

**Parameters:**
- `token` - Token string in format `{token_hex}.{salt_hex}`
- `expectedHash` - Expected PBKDF2-derived hash (40-char hex string)

**Returns:** `boolean`

## License

ISC
