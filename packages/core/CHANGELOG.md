# @lti-tool/core

## 1.2.0

### Minor Changes

- 64a7763: Publish additional public keys in the JWKS to support key rotation.

  `LTIConfig` gains an optional `additionalPublicKeys` array of publish-only public keys (`{ publicKey: CryptoKey; kid: string; alg? }`, `alg` defaulting to `RS256`). `getJWKS()` now publishes the active signing key followed by each additional key, so a rotated-away key can stay verifiable during the overlap window required by the 1EdTech Security Framework. The single active `keyPair` remains the only signer.

  The `LTITool` constructor throws on a duplicate `kid` across published keys, and warns when additional keys are configured while `security.keyId` is left at its `'main'` default. A config with no `additionalPublicKeys` produces byte-identical JWKS output and identical signing behavior — the change is additive with no migration. Adds a Key Management guide covering key storage, rotation, and revocation.

## 1.1.5

### Patch Changes

- 3033bd4: Require nonces to be stored before validation succeeds.

  MySQL, PostgreSQL, and DynamoDB now store issued nonces during login and atomically mark existing unexpired nonces as used during launch validation. Unknown, expired, or already-used nonces now fail validation instead of being accepted on first sight.

  The obsolete `nonceExpirationSeconds` storage adapter option has been removed from MySQL, PostgreSQL, and DynamoDB configuration types. Nonce expiration is controlled by the core LTI security config and passed to storage as the issued nonce `expiresAt` value.

  SQL migrations backfill existing nonce rows as consumed so historical replay-protection records cannot become valid unused issued nonces after upgrade.

## 1.1.4

### Patch Changes

- 13da520: feature: core - Bind LTI launch target to login state. Package updates.

## 1.1.3

### Patch Changes

- 5ee55b0: Accept LTI 1.3 launch ID tokens whose `aud` claim is an array containing the
  tool client ID, and reject additional audiences unless configured as trusted.
  Launch verification now binds the client configuration from signed state before
  checking the ID token, and session creation preserves the verified client ID for
  multi-audience launches.

## 1.1.2

### Patch Changes

- 2e944db: Emit Node-compatible ESM consistently across published packages by using NodeNext module resolution and explicit `.js` extensions for internal relative imports.

## 1.1.1

### Patch Changes

- 164dc9d: Preserve AGS platform extension fields, support standard result filters and schema fields, and allow callers to read specific line item results and details.

## 1.1.0

### Minor Changes

- 850ba01: Add platform profile system for LTI dynamic registration with Canvas and Sakai support, fix single-service form submissions from HTML. -- @ottenhoff 🎉 #100

## 1.0.7

### Patch Changes

- b0a98e0: Resiliency -- retry launch JWT verification on JWKS kid miss -- @ottenhoff 🎉 #94

## 1.0.6

### Patch Changes

- a5404db: Sakai compatibility — @ottenhoff 🎉 #83

## 1.0.5

### Patch Changes

- fbb5e07: Update package dependencies

## 1.0.4

### Patch Changes

- ed13d10: Package version updates

## 1.0.3

### Patch Changes

- adf5f88: Add link to documentation site for all packages

## 1.0.2

### Patch Changes

- 96f0075: Package updates

## 1.0.1

### Patch Changes

- 162f5e0: Initial commit of production MySql storage adapter.

## 1.0.0

### Major Changes

- 3bcba99: First stable release of LTI 1.3 toolkit for Node.js.
  - Add ltiServiceFetch utility with automatic User-Agent injection for Canvas API compliance (effective January 2026)
  - Add HTML escaping utility for XSS prevention in dynamic registration flows
  - Complete LTI 1.3 specification: OIDC authentication, AGS, NRPS, Deep Linking, Dynamic Registration
  - Serverless-native design optimized for AWS Lambda and Cloudflare Workers
  - Cookie-free session management for iframe compatibility

## 0.14.1

### Patch Changes

- 25534f8: Fix score and results endpoint to use a cleansed ags line item endpoint without search params.

## 0.14.0

### Minor Changes

- e9141eb: Support additional canvas deep linking placements

## 0.13.2

### Patch Changes

- 865a510: Improve error messaging for LTITool

## 0.13.1

### Patch Changes

- 7bb4c98: Improve JSDoc for service layers

## 0.13.0

### Minor Changes

- d5a2793: Pass through keyId to utilize in kid when signing the Deep Linking JWT

## 0.12.2

### Patch Changes

- 48bd2b5: Update github actions to use npm trusted publishing.

## 0.12.1

### Patch Changes

- 157b99d: Update third party dependencies

## 0.12.0

### Minor Changes

- 3426ca4: Implement dynamic registration

## 0.11.1

### Patch Changes

- 359a3fe: Update dependencies

## 0.11.0

### Minor Changes

- 7c87338: Add NRPS implementation for retrieving course membership and user roles

## 0.10.0

### Minor Changes

- 9cdc0c7: Add AGS implementation and refactor Hono integration to simple handler pattern

## 0.9.0

### Minor Changes

- 5257caa: Initial release of LTI Tool library
  - Complete LTI 1.3 implementation with security validation
  - Hono framework integration for serverless deployments
  - DynamoDB storage adapter with caching
  - In-memory storage adapter for development
  - Cookie-free session management
  - Assignment and Grade Services (AGS) support
  - Deep Linking support
  - Comprehensive TypeScript support
