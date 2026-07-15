# lti-tool core

<p align="center">
  <a href="https://www.npmjs.com/package/@lti-tool/core"><img alt="npm" src="https://img.shields.io/npm/dm/%40lti-tool%2Fcore?style=flat-square" /></a>
  <a href="https://github.com/lti-tool/lti-tool/actions/workflows/release.yml"><img alt="Build status" src="https://img.shields.io/github/actions/workflow/status/lti-tool/lti-tool/ci.yml?style=flat-square&branch=dev" /></a>
</p>
<p align="center">Modern LTI 1.3 toolkit, built for TypeScript.</p>

## Core Features

- **LTI 1.3 OIDC Flow** - Complete authentication and launch verification
- **Security** - JWT verification, nonce validation, replay attack prevention
- **Assignment and Grade Services (AGS)** - Score submission to LMS
- **Session Management** - Secure session creation and retrieval
- **Client Management** - Platform and deployment configuration

## Installation

```bash
npm install @lti-tool/core
```

## Quick Start

```typescript
import { LTITool } from '@lti-tool/core';

const ltiTool = new LTITool({
  stateSecret: new TextEncoder().encode('your-secret-key'),
  keyPair, // Your RSA keypair
  storage: new MemoryStorage(),
});

// Configure your LMS
const clientId = await ltiTool.addClient({/* ... */});
await ltiTool.addDeployment(clientId, {/* ... */});

// Handle LTI flow
const authUrl = await ltiTool.handleLogin(loginParams);
const payload = await ltiTool.verifyLaunch(idToken, state);
const session = await ltiTool.createSession(payload);
```

When creating a session from a payload not returned directly by `verifyLaunch` on
the same `LTITool` instance, pass the verified client ID as the second argument
if the launch ID token contains multiple audiences.

## Documentation

- [API Reference](https://docs.lti-tool.dev) - Complete API documentation
- [Examples](https://github.com/lti-tool/lti-tool-examples) - (Coming soon) Working examples

## Security

Production security features

- JWT signature verification using platform JWKS
- Nonce validation prevents replay attacks
- State verification prevents CSRF
- Client ID and deployment validation
