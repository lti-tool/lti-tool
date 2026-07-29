<div align="center">
  <img src="./media/logo.png" alt="LTI Tool" />
</div>

<p align="center">
  <a href="https://www.npmjs.com/package/@lti-tool/core"><img alt="npm" src="https://img.shields.io/npm/dm/%40lti-tool%2Fcore?style=flat-square" /></a>
  <a href="https://github.com/lti-tool/lti-tool/actions/workflows/ci.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/lti-tool/lti-tool/release.yml" /></a>
</p>

# LTI Tool

<p align="center">Modern LTI 1.3 toolkit, built for TypeScript.</p>

## Why This Library?

The first **serverless-native** LTI 1.3 library for Node.js. Built for modern cloud architectures with pluggable storage and framework adapters.

**Key features**

- **Serverless-first** - Optimized for AWS Lambda, Cloudflare Workers
- **Pluggable storage** - Memory, DynamoDB, PostgreSQL, MySQL, Cloudflare D1
- **Modern frameworks** - Hono (primary), Express/Fastify (planned)
- **Security-focused** - JWT verification, nonce validation, replay attack prevention
- **Performance** - 6.5ms average execution time, scales to zero
- **Cost-effective** - Under $0.001 per 1000 LTI launches

**Fully Implemented LTI 1.3 Specification:**

- ✅ OIDC Authentication Flow
- ✅ Assignment and Grade Services (AGS) - Score submission, line items, results
- ✅ Names and Role Provisioning Services (NRPS) - Member roster access
- ✅ Deep Linking - Content selection and placement
- ✅ Dynamic Registration - Automated tool registration
- ✅ Security - JWT verification, nonce validation, replay attack prevention

### Future Releases

- **Examples Repository** - Comprehensive example implementations
- **Framework Support** - Express, Fastify, Astro, React, Angular

## Documentation

- [API Reference](https://docs.lti-tool.dev) - Complete API documentation

## Hono Quick Start

Create a new Hono app

```bash
npm create hono@latest
```

Install the packages

```bash
npm install @lti-tool/core @lti-tool/hono @lti-tool/memory
```

Create a minimal Hono powered LTI tool

```typescript
import { Hono } from 'hono';
import { LTITool } from '@lti-tool/core';
import {
  jwksRouteHandler,
  launchRouteHandler,
  loginRouteHandler,
  secureLTISession,
} from '@lti-tool/hono';
import { MemoryStorage } from '@lti-tool/memory';

// Generate keypair (use proper key management in production)
const keyPair = await crypto.subtle.generateKey(
  {
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  },
  true,
  ['sign', 'verify'],
);

const ltiConfig = {
  stateSecret: new TextEncoder().encode('your-secret-key'),
  keyPair,
  storage: new MemoryStorage(),
};

const ltiTool = new LTITool(ltiConfig);

// Add your LMS configuration
const clientId = await ltiTool.addClient({
  name: 'Moodle Sandbox',
  clientId: 'your-client-id-from-moodle',
  iss: 'https://sandbox.moodledemo.net',
  jwksUrl: 'https://sandbox.moodledemo.net/mod/lti/certs.php',
  authUrl: 'https://sandbox.moodledemo.net/mod/lti/auth.php',
  tokenUrl: 'https://sandbox.moodledemo.net/mod/lti/token.php',
});

await ltiTool.addDeployment(clientId, {
  deploymentId: 'your-deployment-id-from-moodle',
  name: 'Default Deployment',
});

const app = new Hono();

// Add LTI routes
app.get('/lti/jwks', jwksRouteHandler(ltiConfig));
app.post('/lti/launch', launchRouteHandler(ltiConfig));
app.post('/lti/login', loginRouteHandler(ltiConfig));

// Protect routes with LTI session
app.use('/protected/*', secureLTISession(ltiConfig));

app.get('/protected/content', (c) => {
  const session = c.get('ltiSession');
  return c.json({ message: `Hello ${session.user.name}` });
});
```

## Performance

Optimized for serverless with impressive performance metrics

| Operation         | Execution Time |
| ----------------- | -------------- |
| Login/JWKS        | 3-5ms          |
| Launch (heaviest) | 12-15ms        |
| **Average**       | **6.5ms**      |

## Architecture

### Packages

| Package                                         | Description                   | Use Case                       |
| ----------------------------------------------- | ----------------------------- | ------------------------------ |
| [`@lti-tool/core`](./packages/core)             | Core LTI 1.3 implementation   | Required for all setups        |
| [`@lti-tool/hono`](./packages/hono)             | Hono framework integration    | Serverless APIs                |
| [`@lti-tool/memory`](./packages/memory)         | In-memory storage adapter     | Development and testing        |
| [`@lti-tool/dynamodb`](./packages/dynamodb)     | DynamoDB storage adapter      | Production AWS deployments     |
| [`@lti-tool/postgresql`](./packages/postgresql) | PostgreSQL storage adapter    | Production SQL deployments     |
| [`@lti-tool/mysql`](./packages/mysql)           | MySQL storage adapter         | Production SQL deployments     |
| [`@lti-tool/d1`](./packages/d1)                 | Cloudflare D1 storage adapter | Cloudflare Workers deployments |

### Storage Adapters

Pluggable storage system supports multiple backends

- **Memory** - Development and testing
- **DynamoDB** - Production AWS (with caching)
- **PostgreSQL** - Production SQL deployments
- **MySQL** - Production SQL deployments
- **Cloudflare D1** - Cloudflare Workers deployments
- **Custom** - Implement the `LTIStorage` interface

### Framework Support

- **Hono** - Primary target (serverless-optimized)
- **TanStack** - Planned
- **Fastify** - Planned
- **Astro** - Planned
- **Express** - Planned

## Testing with Moodle Sandbox

Test your implementation with the public Moodle sandbox

### 1. Access Moodle Sandbox

- URL: https://sandbox.moodledemo.net/
- Login with administrator credentials (available on the site)

### 2. Configure LTI Tool

1. Go to **Site Administration** → **Plugins** → **Activity modules** → **External tool** → **Manage tools**
2. Click **"configure a tool manually"**
3. Fill in the configuration

| Field              | Value                                |
| ------------------ | ------------------------------------ |
| Tool name          | `lti-tool`                           |
| Tool URL           | `https://your-domain.com`            |
| LTI version        | **LTI 1.3**                          |
| Public key type    | **Keyset URL**                       |
| Public keyset      | `https://your-domain.com/lti/jwks`   |
| Login URL          | `https://your-domain.com/lti/login`  |
| Redirection URI(s) | `https://your-domain.com/lti/launch` |

4. Enable services
   - **IMS LTI Assignment and Grade Services**: Use this service for grade sync
   - **IMS LTI Names and Role Provisioning**: Use this service to retrieve members
   - **Tool Settings**: Use this service

5. Set privacy options (optional)
   - Share launcher's name: **Always**
   - Share launcher's email: **Always**

### 3. Get Configuration Details

After saving, click the magnifying glass to view tool details and update your code

```typescript
const clientId = await ltiTool.addClient({
  name: 'Moodle Sandbox',
  clientId: 'YOUR_CLIENT_ID_FROM_MOODLE', // Copy from tool details
  iss: 'https://sandbox.moodledemo.net',
  jwksUrl: 'https://sandbox.moodledemo.net/mod/lti/certs.php',
  authUrl: 'https://sandbox.moodledemo.net/mod/lti/auth.php',
  tokenUrl: 'https://sandbox.moodledemo.net/mod/lti/token.php',
});

await ltiTool.addDeployment(clientId, {
  deploymentId: 'YOUR_DEPLOYMENT_ID_FROM_MOODLE', // Copy from tool details
  name: 'Default Deployment',
});
```

### 4. Add to Course

1. Edit any course
2. Add activity → **External tool**
3. Select your configured tool
4. Test the launch!

## Security

Production-ready security features

- **JWT Signature Verification** - Using platform JWKS
- **Nonce Validation** - Prevents replay attacks
- **State Verification** - CSRF protection
- **Client ID Validation** - Ensures proper tool targeting
- **Deployment Verification** - Validates deployment context
- **Cookie-Free Design** - Works in all iframe contexts, immune to 3rd party cookie restrictions

> **Production Note**: The quick start example uses `crypto.subtle.generateKey()` for simplicity. In production, store the private key in a secrets manager (AWS Parameter Store SecureString, AWS Secrets Manager, HashiCorp Vault, etc.) and load it at startup. See the [Key Management guide](https://docs.lti-tool.dev/documents/Key_Management.html) for where the key should live and how to rotate or revoke it.

## Examples (coming soon)

Examples repository coming soon. Watch this repo for updates!

## Get Involved

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

**Need help?** [Open an issue](https://github.com/lti-tool/lti-tool/issues) or [start a discussion](https://github.com/lti-tool/lti-tool/discussions)
