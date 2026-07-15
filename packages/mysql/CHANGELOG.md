# @lti-tool/mysql

## 2.0.1

### Patch Changes

- 59921b6: Apply package security updates

## 2.0.0

### Major Changes

- 3033bd4: Require nonces to be stored before validation succeeds.

  MySQL, PostgreSQL, and DynamoDB now store issued nonces during login and atomically mark existing unexpired nonces as used during launch validation. Unknown, expired, or already-used nonces now fail validation instead of being accepted on first sight.

  The obsolete `nonceExpirationSeconds` storage adapter option has been removed from MySQL, PostgreSQL, and DynamoDB configuration types. Nonce expiration is controlled by the core LTI security config and passed to storage as the issued nonce `expiresAt` value.

  SQL migrations backfill existing nonce rows as consumed so historical replay-protection records cannot become valid unused issued nonces after upgrade.

### Patch Changes

- Updated dependencies [3033bd4]
  - @lti-tool/core@1.1.5

## 1.1.2

### Patch Changes

- 13da520: feature: core - Bind LTI launch target to login state. Package updates.
- Updated dependencies [13da520]
  - @lti-tool/core@1.1.4

## 1.1.1

### Patch Changes

- 2e944db: Emit Node-compatible ESM consistently across published packages by using NodeNext module resolution and explicit `.js` extensions for internal relative imports.
- Updated dependencies [2e944db]
  - @lti-tool/core@1.1.2

## 1.1.0

### Minor Changes

- 850ba01: Add platform profile system for LTI dynamic registration with Canvas and Sakai support, fix single-service form submissions from HTML. -- @ottenhoff 🎉 #100

### Patch Changes

- Updated dependencies [850ba01]
  - @lti-tool/core@1.1.0

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

- d0ea23e: First stable release of MySQL storage adapter.
  - Production-ready storage for MySQL deployments
  - Built-in caching support for improved performance
  - Full support for clients, deployments, sessions, and nonces

## 0.10.1

### Patch Changes

- ca9131c: ci bump to test github ci cd

## 0.10.0

### Minor Changes

- 162f5e0: Initial commit of production MySql storage adapter.

### Patch Changes

- Updated dependencies [162f5e0]
  - @lti-tool/core@1.0.1
