---
'@lti-tool/core': minor
---

Publish additional public keys in the JWKS to support key rotation.

`LTIConfig` gains an optional `additionalPublicKeys` array of publish-only public keys (`{ publicKey: CryptoKey; kid: string; alg? }`, `alg` defaulting to `RS256`). `getJWKS()` now publishes the active signing key followed by each additional key, so a rotated-away key can stay verifiable during the overlap window required by the 1EdTech Security Framework. The single active `keyPair` remains the only signer.

The `LTITool` constructor throws on a duplicate `kid` across published keys, and warns when additional keys are configured while `security.keyId` is left at its `'main'` default. A config with no `additionalPublicKeys` produces byte-identical JWKS output and identical signing behavior — the change is additive with no migration. Adds a Key Management guide covering key storage, rotation, and revocation.
