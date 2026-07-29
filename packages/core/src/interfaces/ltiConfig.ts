import type { Logger } from 'pino';

import type { LTIStorage } from './ltiStorage.js';

export interface CanvasDynamicRegistrationConfig {
  /** Optional Canvas-specific privacy level for launches */
  privacyLevel?: 'public' | 'name_only' | 'email_only' | 'anonymous';
  /** Optional Canvas-specific stable identifier for correlating tool deployments */
  toolId?: string;
  /** Optional Canvas-specific vendor string */
  vendor?: string;
  /** Optional OIDC client URI shown to administrators in Canvas */
  clientUri?: string;
  /** Optional secondary domains included in the Canvas tool configuration */
  secondaryDomains?: string[];
  /** Optional Canvas resource-link placements to expose during registration */
  resourceLinkPlacements?: string[];
  /** Optional Canvas deep-link placements; defaults to the common Canvas set when omitted */
  deepLinkPlacements?: string[];
}

/** Dynamic registration configuration for LTI 1.3 tool registration */
export interface DynamicRegistrationConfig {
  /** Base URL of the LTI tool (e.g., 'https://my-tool.com') */
  url: string;
  /** Display name shown to users in the LMS (e.g., 'My Learning Tool') */
  name: string;
  /** Optional description of the tool's functionality */
  description?: string;
  /** Optional URL to tool logo image for LMS display */
  logo?: string;
  /** Additional redirect URIs beyond the default /lti/launch endpoint */
  redirectUris?: string[];
  /** Optional custom deep linking content selection endpoint (defaults to {url}/lti/deep-linking) */
  deepLinkingUri?: string;
  /** Optional custom login endpoint (defaults to {url}/lti/login) */
  loginUri?: string;
  /** Optional custom launch endpoint (defaults to {url}/lti/launch) */
  launchUri?: string;
  /** Optional custom JWKS endpoint (defaults to {url}/lti/jwks) */
  jwksUri?: string;
  /** Optional platform-specific dynamic registration extensions */
  platforms?: {
    /** Optional Canvas-specific registration settings */
    canvas?: CanvasDynamicRegistrationConfig;
  };
}

/**
 * A public key published in the tool's JWKS in addition to the active signing key.
 *
 * Entries are publish-only: they are never used to sign anything. Their purpose is
 * to keep a previous key verifiable during a rotation overlap, or to publish a key
 * that is signed outside this library.
 */
export interface AdditionalPublicKey {
  /** Public key to publish. Import from PEM with jose's `importSPKI`, or from JWK with `importJWK`. */
  publicKey: CryptoKey;
  /** Key identifier for this key. Must be unique across the active key and all other additional keys. */
  kid: string;
  /** Algorithm published for this key (defaults to 'RS256') */
  alg?: string;
}

/**
 * Configuration object for initializing an LTI Tool instance.
 * Contains cryptographic keys, secrets, and storage adapter.
 */
export interface LTIConfig {
  /** Secret key used for signing state JWTs during OIDC flow (minimum 32 bytes recommended) */
  stateSecret: Uint8Array;

  /** RSA key pair for signing JWTs and providing JWKS endpoint */
  keyPair: CryptoKeyPair;

  /**
   * Additional public keys to publish in the JWKS alongside `keyPair`'s public key.
   *
   * These are publish-only: `keyPair` remains the only signer. Use them to keep a
   * previous key verifiable while tokens signed with it are still in flight during a
   * rotation. Each `kid` must be unique across the active key and all additional keys,
   * and each entry's `alg` defaults to `'RS256'`.
   */
  additionalPublicKeys?: AdditionalPublicKey[];

  /** Storage adapter for persisting platforms, sessions, and nonces */
  storage: LTIStorage;

  /** Optional pino logger */
  logger?: Logger;

  /** Security configuration options */
  security?: {
    /** Key ID for JWKS and JWT signing (defaults to 'main') */
    keyId?: string;
    /** State JWT expiration time in seconds (defaults to 600 = 10 minutes) */
    stateExpirationSeconds?: number;
    /** Nonce expiration time in seconds (defaults to 600 = 10 minutes) */
    nonceExpirationSeconds?: number;
    /**
     * Additional JWT audience values to trust when a launch ID Token includes
     * audiences besides this tool's client ID. Most tools should leave this unset.
     */
    trustedAudiences?: string[];
  };

  /** Dynamic registration configuration for LTI 1.3 tool registration */
  dynamicRegistration?: DynamicRegistrationConfig;
}
