<div align="center">
  <a href="https://docs.fiveonefour.com/moose/">
    <picture>
      <img alt="MooseStack logo" src="https://raw.githubusercontent.com/514-labs/moose/main/logo-m-light.png" height="128">
    </picture>
  </a>
  <h1>MooseStack</h1>

<a href="https://www.fiveonefour.com"><img alt="MooseStack logo" src="https://img.shields.io/badge/MADE%20BY-Fiveonefour-black.svg"></a>
<a href="https://github.com/514-labs/express-pbkdf2-api-key-auth/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/514-labs/express-pbkdf2-api-key-auth/actions/workflows/ci.yml/badge.svg?branch=main"></a>
<a href="https://www.npmjs.com/package/@514labs/express-pbkdf2-api-key-auth?activeTab=readme"><img alt="NPM version" src="https://img.shields.io/npm/v/%40514labs%2Fpbkdf2-api-key-auth?logo=npm"></a>
<a href="https://join.slack.com/t/moose-community/shared_invite/zt-2fjh5n3wz-cnOmM9Xe9DYAgQrNu8xKxg"><img alt="MooseStack Community" src="https://img.shields.io/badge/Slack-MooseStack_community-purple.svg?logo=slack"></a>
<a href="LICENSE"><img alt="MIT License" src="https://img.shields.io/badge/License-MIT-yellow.svg"></a>

</div>

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
