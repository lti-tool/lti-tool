# @lti-tool/hono

## 1.1.0

### Minor Changes

- 850ba01: Add platform profile system for LTI dynamic registration with Canvas and Sakai support, fix single-service form submissions from HTML. -- @ottenhoff 🎉 #100

### Patch Changes

- Updated dependencies [850ba01]
  - @lti-tool/core@1.1.0

## 1.0.5

### Patch Changes

- 8e1efb1: Sakai compatibility — @ottenhoff 🎉 #82

## 1.0.4

### Patch Changes

- fbb5e07: Update package dependencies
- Updated dependencies [fbb5e07]
  - @lti-tool/core@1.0.5

## 1.0.3

### Patch Changes

- ed13d10: Package version updates
- Updated dependencies [ed13d10]
  - @lti-tool/core@1.0.4

## 1.0.2

### Patch Changes

- adf5f88: Add link to documentation site for all packages
- Updated dependencies [adf5f88]
  - @lti-tool/core@1.0.3

## 1.0.1

### Patch Changes

- 96f0075: Package updates
- Updated dependencies [96f0075]
  - @lti-tool/core@1.0.2

## 1.0.0

### Major Changes

- 3bcba99: First stable release of Hono framework integration for LTI 1.3.
  - Production-ready route handlers for login, launch, JWKS, deep linking, and dynamic registration
  - LTI session middleware for protected routes

### Patch Changes

- Updated dependencies [3bcba99]
  - @lti-tool/core@1.0.0

## 0.12.2

### Patch Changes

- bc01f95: Update hono usage documentation

## 0.12.1

### Patch Changes

- 48bd2b5: Update github actions to use npm trusted publishing.
- Updated dependencies [48bd2b5]
  - @lti-tool/core@0.12.2

## 0.12.0

### Minor Changes

- 46aff4d: Add comprehensive error handling to all LTI route handlers with proper HTTP status codes, structured error responses, and request context logging. Added zod dependency for type-safe error checking.

## 0.11.0

### Minor Changes

- 3426ca4: Implement dynamic registration

### Patch Changes

- Updated dependencies [3426ca4]
  - @lti-tool/core@0.12.0

## 0.10.1

### Patch Changes

- 359a3fe: Update dependencies
- Updated dependencies [359a3fe]
  - @lti-tool/core@0.11.1

## 0.10.0

### Minor Changes

- 9cdc0c7: Add AGS implementation and refactor Hono integration to simple handler pattern

### Patch Changes

- Updated dependencies [9cdc0c7]
  - @lti-tool/core@0.10.0

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

### Patch Changes

- Updated dependencies [5257caa]
  - @lti-tool/core@0.9.0
