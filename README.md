# express-pbkdf2-api-key-auth

Express middleware for PBKDF2 API key authentication. Zero external dependencies (uses Node.js crypto). Compatible with [moosestack](https://github.com/514-labs/moosestack) token format.

## Installation

```bash
npm install @514-labs/express-pbkdf2-api-key-auth
```

## Generating API Keys

Use the CLI to generate an API key pair:

```bash
npx generate-api-key
```

Output:

```
API Key Hash (store server-side):
1ee1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxf64b

Bearer Token (client sends in header; Authorization: Bearer ...):
3cb3xxxxxxxxxxxxxxxxxxxxxxxx0dad.1f67xxxxxxxxxxxxxxxxxxxxxxxx6f33
```

Or programmatically:

```javascript
import { generateApiKey } from "@514-labs/express-pbkdf2-api-key-auth";

const { bearerToken, apiKeyHash } = generateApiKey();
```

## Usage

```javascript
import express from "express";
import { createAuthMiddleware } from "@514-labs/express-pbkdf2-api-key-auth";

const authMiddleware = createAuthMiddleware((req) => {
  return process.env.API_KEY_HASH;
});

const app = express();
app.use(authMiddleware);

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

The token format is compatible with [moosestack](https://github.com/514-labs/moosestack)'s `moose generate hash-token` command:

- Token: 16 random bytes (32-char hex string)
- Salt: 16 random bytes (32-char hex string)
- Hash: PBKDF2-HMAC-SHA256, 1000 iterations, 20-byte output
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

### `generateApiKey()`

Generates a new API key pair.

**Returns:** `{ bearerToken: string, apiKeyHash: string }`
