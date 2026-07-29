---
title: Key Management
---

# Key Management

Your tool signs two kinds of short-lived artifact with a single RSA private key:

- **Client assertions** for OAuth2 service calls (AGS, NRPS) - expire 5 minutes after they are minted.
- **Deep Linking responses** - expire 10 minutes after they are minted.

Platforms verify those signatures against the public keys your tool publishes at its JWKS endpoint. Launch verification goes the other way - your tool verifies the _platform's_ signature - and needs none of your key material.

This guide covers what key material the library needs, where the private key should live, and the two procedures that keep it healthy: **[rotation](#rotating-a-key)** (planned, with an overlap window) and **[revocation](#revoking-a-key)** (compromise, no overlap). They are different procedures with an opposite rule about overlap, so keep them straight.

## What the library needs

The library is a **mechanism, not a policy**. It signs with the key material you hand it and publishes what you tell it to publish. It does not generate, schedule, age, or persist keys - those are your application's to own, because only your application knows your storage, your compute environment, and your rotation cadence.

Two things go into {@link @lti-tool/core!LTIConfig | `LTIConfig`}:

- **`keyPair`** - a `CryptoKeyPair`. Its private half is the one and only signer; its public half is always published in the JWKS.
- **`additionalPublicKeys`** - an optional array of extra **public** keys to publish alongside the active one. These are never used to sign. Their entire purpose is to keep a _previous_ public key verifiable during a rotation, or to publish a key that was signed outside this library.

```typescript
import { importPKCS8, importSPKI } from 'jose';

const ltiTool = new LTITool({
  stateSecret,
  storage,
  keyPair: {
    privateKey: await importPKCS8(activePrivatePem, 'RS256'),
    publicKey: await importSPKI(activePublicPem, 'RS256'),
  },
  security: { keyId: '2026-02' },
  additionalPublicKeys: [
    // The key we just rotated away from, still verifiable while its tokens drain.
    { publicKey: await importSPKI(previousPublicPem, 'RS256'), kid: '2026-01' },
  ],
});
```

Every published key needs a **unique `kid`**. The active key's `kid` comes from `security.keyId` (default `'main'`); each additional key carries its own. The constructor **throws** if any two published keys share a `kid` - two keys under the same `kid` make a platform's key selection nondeterministic, so this is rejected at boot rather than surfacing as a verification failure days later.

If you configure `additionalPublicKeys` while leaving `security.keyId` at its default `'main'`, the constructor logs a warning. `'main'` works, but it means you have not yet chosen deliberate key IDs - and your next rotation depends on being able to tell the active key apart from the retired ones. Set a `keyId` you control (a date like `2026-02` reads well) before you rotate.

## Where the private key belongs

The one principle that governs storage:

> The private key should be decryptable by exactly one thing: the role your compute layer runs as.

Everything below is a way of spelling that principle for a specific provider. None of it is IAM policy, provisioning, or product-selection advice - that is yours to own; these are just the resting places that satisfy the principle.

| Provider           | Where the key rests                                | The detail that matters                                                                                                                                                                                          |
| ------------------ | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| AWS                | Parameter Store `SecureString`, or Secrets Manager | Encrypt with a **customer-managed KMS key**, not the AWS-managed `aws/ssm` default. A customer-managed key is one whose key policy _you_ write, so you can scope decryption to exactly your task/execution role. |
| GCP                | Secret Manager                                     | Grant `secretmanager.secretAccessor` to the service account your workload runs as - and nothing else.                                                                                                            |
| Azure              | Key Vault                                          | Access via the workload's managed identity; the key never becomes an app setting.                                                                                                                                |
| HashiCorp Vault    | KV v2 secrets engine                               | Auth with the workload's identity (Kubernetes, AWS IAM, etc.); leases are short and audited.                                                                                                                     |
| Cloudflare Workers | Secrets Store, or a Worker secret binding          | Bound to the Worker at deploy time and readable only from within the Worker's isolate.                                                                                                                           |

There is deliberately **no environment-variable row**. An environment variable is _how a key arrives_ at your process, not _where it rests_ - it is a delivery channel, and putting it in the same table as a secrets manager is a category error. If a secret manager hands your key to the process as an env var at boot, fine; the key still _rests_ in the manager. What you must not do is treat a plaintext env var in a dashboard or a `.env` file as the key's home.

### A note on KMS asymmetric signing

AWS KMS (and its GCP/Azure equivalents) can hold an asymmetric private key that **never leaves the HSM** - you sign by calling the KMS `Sign` API and publish the public half you fetch with `GetPublicKey`. It is a genuinely strong posture: the private key is unexportable.

It is also **a different model than this library implements**, and there is no seam to plug it in. This library signs _in-process_ with a `CryptoKey` you hold in memory. KMS-held signing would put a network round-trip on the critical path of _every_ signature and subject your signing rate to KMS request quotas and throttling - real costs, on a hot path, that in-process signing does not pay. If that trade is right for your threat model, you would need your own signing path; publishing the public key here would only cover the JWKS half. This is called out so the choice is deliberate, not so it is discouraged.

## Rotating a key

Rotation is **planned**. The goal is that at no instant is a valid, in-flight token unverifiable - so the old and new keys overlap in the published set for a window.

1. **Generate** a new keypair and give it a new `kid` (e.g. `2026-03`). Never reuse a `kid`.
2. **Switch the signer**: set `keyPair` to the new pair and `security.keyId` to its new `kid`. From this moment every new signature uses the new key. This is an atomic config change, not a gradual roll.
3. **Keep the old public key published**: move the _previous_ public key into `additionalPublicKeys` with its original `kid`. Platforms that cached your old JWKS, and tokens already signed with the old key, stay verifiable.
4. **Wait out the overlap**, then **remove** the old entry from `additionalPublicKeys`. Once nothing signed with the old key can still be within its expiry, the old public key has no job left.

**How long is the overlap?** Derive it, do not copy a number. The longest-lived thing you sign is a Deep Linking response at **10 minutes**; client assertions are **5**. So 10 minutes after you switch the signer, no token bearing the old `kid` can still be valid. Any figure beyond that - an hour, a day - is padding _you_ choose to absorb clock skew and slow platform JWKS caches. It is not a requirement the library imposes; it falls out of your own token lifetimes. Pick a number you can defend and keep the retention consistent with it.

## Revoking a key

Revocation is for **compromise** - you believe the private key has leaked. The rule inverts:

> Remove the compromised key from the published set **immediately, with no overlap window.**

1. **Generate** a fresh keypair with a new `kid` and switch the signer to it (steps 1–2 of rotation).
2. **Do not** place the compromised public key in `additionalPublicKeys`. Remove it from the published set entirely, right now.

> **Why no overlap?** The overlap window that makes rotation safe is exactly what makes revocation dangerous. As long as the compromised public key is published, an attacker holding the stolen _private_ key can keep minting assertions that platforms will accept. Every extra minute of publication is another minute the attacker is trusted. You accept the brief breakage of any legitimate in-flight tokens signed with the old key - a few minutes of failed verifications - because the alternative is continuing to honor the attacker's signatures. Breakage is the correct trade here.

If you are unsure whether you are rotating or revoking: if the old private key might be in someone else's hands, it is a revocation. Treat it as one.
