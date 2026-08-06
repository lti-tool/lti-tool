import * as z from 'zod';

import { LTI_CLAIM_TOOL_CONFIGURATION } from '../../../constants.js';

import { LTIMessagesArraySchema } from './ltiMessages.schema.js';

/**
 * Zod schema for LTI tool configuration section within tool registration payload.
 * Contains LTI-specific metadata about the tool being registered with the platform.
 *
 * @property domain - Tool's domain name for security validation and CORS policies
 * @property description - Optional human-readable description of the tool's purpose
 * @property target_link_uri - Default launch URL where the platform should send LTI requests
 * @property claims - Array of JWT claims the tool requires from launch requests (e.g., 'iss', 'sub', 'name', 'email')
 * @property messages - Array of LTI message types the tool supports (ResourceLink, DeepLinking, etc.)
 */
const LTIToolConfigurationSchema = z
  .object({
    domain: z.string(),
    description: z.string().optional(),
    target_link_uri: z.url(),
    secondary_domains: z.array(z.string()).optional(),
    custom_parameters: z.record(z.string(), z.string()).optional(),
    claims: z.array(z.string()),
    messages: LTIMessagesArraySchema,
    'https://canvas.instructure.com/lti/privacy_level': z
      .enum(['public', 'name_only', 'email_only', 'anonymous'])
      .optional(),
    'https://canvas.instructure.com/lti/tool_id': z.string().optional(),
    'https://canvas.instructure.com/lti/vendor': z.string().optional(),
  })
  .loose();

/**
 * Zod schema for validating LTI 1.3 dynamic registration payload sent to platforms.
 * This payload is constructed by the tool and sent to the platform's registration endpoint
 * to register the tool and request specific OAuth scopes and LTI services.
 *
 * @property application_type - Always 'web' for LTI tools
 * @property response_types - OAuth response types, always ['id_token'] for LTI 1.3
 * @property grant_types - OAuth grant types requested ('implicit' for launches, 'client_credentials' for services)
 * @property initiate_login_uri - Tool's login initiation endpoint for OIDC flow
 * @property redirect_uris - Array of valid redirect URIs where the platform can send responses
 * @property client_name - Human-readable name of the tool being registered
 * @property jwks_uri - Tool's JSON Web Key Set endpoint for signature verification
 * @property logo_uri - Optional URL to the tool's logo image
 * @property scope - Optional OAuth scopes being requested (AGS, NRPS, etc.)
 * @property token_endpoint_auth_method - Always 'private_key_jwt' for LTI 1.3 security
 * @property LTI_CLAIM_TOOL_CONFIGURATION - LTI-specific tool configuration
 */
export const ToolRegistrationPayloadSchema = z
  .object({
    application_type: z.literal('web'),
    response_types: z.array(z.literal('id_token')),
    grant_types: z.array(z.enum(['implicit', 'client_credentials'])),
    initiate_login_uri: z.url(),
    redirect_uris: z.array(z.url()),
    client_name: z.string(),
    client_uri: z.url().optional(),
    jwks_uri: z.url(),
    logo_uri: z.url().optional(),
    scope: z.string().optional(),
    token_endpoint_auth_method: z.literal('private_key_jwt'),
    [LTI_CLAIM_TOOL_CONFIGURATION]: LTIToolConfigurationSchema,
  })
  .loose();

export type ToolRegistrationPayload = z.infer<typeof ToolRegistrationPayloadSchema>;
export type LTIToolConfiguration = z.infer<typeof LTIToolConfigurationSchema>;
