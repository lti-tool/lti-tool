import * as z from 'zod';

import { LTI_CLAIM_TOOL_CONFIGURATION } from '../../../constants.js';

import { LTIMessagesArraySchema } from './ltiMessages.schema.js';

/**
 * Zod schema for LTI tool configuration within dynamic registration response.
 * Contains tool-specific metadata returned by the platform after successful registration.
 *
 * @property domain - Tool's domain name for security validation
 * @property target_link_uri - Optional default launch URL for the tool
 * @property custom_parameters - Optional custom parameters passed to the tool
 * @property claims - Array of JWT claims the tool requires (e.g., 'iss', 'sub', 'name', 'email')
 * @property messages - Array of LTI message types the tool supports
 * @property version - Optional tool version string
 * @property deployment_id - Optional deployment identifier assigned by the platform
 */
const LTIToolConfigurationResponseSchema = z.object({
  domain: z.string(),
  target_link_uri: z.url().optional(),
  custom_parameters: z.record(z.string(), z.string()).optional(),
  claims: z.array(z.string()),
  messages: LTIMessagesArraySchema,
  version: z.string().optional(),
  deployment_id: z.string().optional(),
});

/**
 * Zod schema for validating LTI 1.3 dynamic registration response from platforms.
 * This response is returned after successfully registering a tool with an LTI platform.
 * Contains the registered client credentials and configuration that the tool needs to store.
 *
 * @property client_id - Unique client identifier assigned by the platform
 * @property registration_client_uri - Optional URI for managing this registration
 * @property registration_access_token - Optional token for registration management
 * @property application_type - Always 'web' for LTI tools
 * @property response_types - OAuth response types, always ['id_token'] for LTI
 * @property grant_types - OAuth grant types supported ('implicit', 'client_credentials')
 * @property initiate_login_uri - Tool's login initiation endpoint
 * @property redirect_uris - Array of valid redirect URIs for the tool
 * @property client_name - Human-readable name of the registered tool
 * @property jwks_uri - Tool's JSON Web Key Set endpoint for signature verification
 * @property logo_uri - Optional URL to the tool's logo image
 * @property token_endpoint_auth_method - Always 'private_key_jwt' for LTI 1.3
 * @property contacts - Optional array of contact email addresses
 * @property scope - Optional OAuth scopes granted to the tool
 * @property LTI_CLAIM_TOOL_CONFIGURATION - LTI-specific tool configuration
 */
export const RegistrationResponseSchema = z.object({
  client_id: z.string(),
  registration_client_uri: z.url().optional(),
  registration_access_token: z.string().optional(),
  application_type: z.literal('web'),
  response_types: z.array(z.literal('id_token')),
  grant_types: z.array(z.enum(['implicit', 'client_credentials'])), // Note: "implicit" not "implict"
  initiate_login_uri: z.url(),
  redirect_uris: z.array(z.url()),
  client_name: z.string(),
  jwks_uri: z.url(),
  logo_uri: z.url().optional().or(z.literal('')),
  token_endpoint_auth_method: z.literal('private_key_jwt'),
  contacts: z.array(z.email()).optional(),
  scope: z.string().optional().or(z.literal('')),
  [LTI_CLAIM_TOOL_CONFIGURATION]: LTIToolConfigurationResponseSchema,
});

export type RegistrationResponse = z.infer<typeof RegistrationResponseSchema>;
