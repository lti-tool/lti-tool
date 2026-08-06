import * as z from 'zod';

import { LTI_CLAIM_PLATFORM_CONFIGURATION } from '../../../constants.js';

/**
 * Zod schema for LTI platform-specific configuration within OpenID Connect Discovery.
 * Contains LTI-specific metadata about the platform's capabilities and supported features.
 *
 * @property product_family_code - Platform identifier (e.g., 'moodle', 'canvas', 'sakai')
 * @property version - Platform version string
 * @property messages_supported - Array of LTI message types the platform supports
 * @property variables - Optional array of custom variable names the platform supports
 */
export const ltiPlatformConfigurationSchema = z.object({
  product_family_code: z.string(),
  version: z.string(),
  messages_supported: z.array(
    z
      .object({
        type: z.string(),
        placements: z.array(z.string()).optional(),
      })
      .loose(),
  ),
  variables: z.array(z.string()).optional(),
});

/**
 * Zod schema for validating OpenID Connect Discovery configuration from LTI 1.3 platforms.
 * This configuration is fetched during dynamic registration to discover platform endpoints,
 * supported features, and security requirements. Used to validate the response from the
 * platform's /.well-known/openid_configuration endpoint.
 *
 * @property issuer - Platform's issuer URL (must match hostname of configuration endpoint)
 * @property authorization_endpoint - OAuth 2.0 authorization endpoint for LTI launches
 * @property registration_endpoint - Dynamic registration endpoint for tool registration
 * @property jwks_uri - JSON Web Key Set endpoint for signature verification
 * @property token_endpoint - OAuth 2.0 token endpoint for service access tokens
 * @property scopes_supported - Array of OAuth scopes the platform supports (AGS, NRPS, etc.)
 * @property LTI_CLAIM_PLATFORM_CONFIGURATION - LTI-specific platform metadata
 */
export const openIDConfigurationSchema = z
  .object({
    issuer: z.url(),
    authorization_endpoint: z.url(),
    registration_endpoint: z.url(),
    jwks_uri: z.url(),
    token_endpoint: z.url(),
    token_endpoint_auth_methods_supported: z.array(z.string()),
    token_endpoint_auth_signing_alg_values_supported: z.array(z.string()),
    scopes_supported: z.array(z.string()),
    response_types_supported: z.array(z.string()),
    id_token_signing_alg_values_supported: z.array(z.string()),
    claims_supported: z.array(z.string()),
    subject_types_supported: z.array(z.string()),
    authorization_server: z.string().optional(),
    [LTI_CLAIM_PLATFORM_CONFIGURATION]: ltiPlatformConfigurationSchema,
  })
  .loose();

export type OpenIDConfiguration = z.infer<typeof openIDConfigurationSchema>;
