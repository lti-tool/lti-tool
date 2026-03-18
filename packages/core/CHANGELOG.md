# @lti-tool/core

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
