# @lti-tool/d1

## 1.0.3

### Patch Changes

- 59921b6: Apply package security updates

## 1.0.2

### Patch Changes

- 3033bd4: Require nonces to be stored before validation succeeds.

  MySQL, PostgreSQL, and DynamoDB now store issued nonces during login and atomically mark existing unexpired nonces as used during launch validation. Unknown, expired, or already-used nonces now fail validation instead of being accepted on first sight.

  The obsolete `nonceExpirationSeconds` storage adapter option has been removed from MySQL, PostgreSQL, and DynamoDB configuration types. Nonce expiration is controlled by the core LTI security config and passed to storage as the issued nonce `expiresAt` value.

  SQL migrations backfill existing nonce rows as consumed so historical replay-protection records cannot become valid unused issued nonces after upgrade.

- Updated dependencies [3033bd4]
  - @lti-tool/core@1.1.5

## 1.0.1

### Patch Changes

- 13da520: feature: core - Bind LTI launch target to login state. Package updates.
- Updated dependencies [13da520]
  - @lti-tool/core@1.1.4

## 1.0.0

### Major Changes

- dfed0c5: First stable release of d1 storage adapter, thanks to @ottenhoff for their contribution!
  - Production-ready storage for d1 deployments
  - Full support for clients, deployments, sessions, and nonces
