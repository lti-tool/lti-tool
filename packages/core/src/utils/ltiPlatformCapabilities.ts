import {
  LTI_AGS_SCOPES,
  LTI_CLAIM_PLATFORM_CONFIGURATION,
  LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  LTI_NRPS_SCOPES,
} from '../constants.js';
import type { OpenIDConfiguration } from '../schemas/index.js';

function hasAnySupportedScope(
  scopesSupported: string[] | undefined,
  scopes: readonly string[],
): boolean {
  if (!scopesSupported) {
    return false;
  }
  return scopes.some((scope) => scopesSupported.includes(scope));
}

function filterSupportedScopes(
  scopesSupported: string[] | undefined,
  scopes: readonly string[],
): string[] {
  if (!scopesSupported) {
    return [];
  }
  return scopes.filter((scope) => scopesSupported.includes(scope));
}

/**
 * Checks if an LTI platform supports Assignment and Grade Services (AGS).
 * Examines the platform's OpenID configuration for AGS-related OAuth scopes.
 *
 * @param config - Platform's OpenID Connect configuration from discovery endpoint
 * @returns True if the platform supports any AGS scopes, false otherwise
 *
 * @example
 * ```typescript
 * if (hasAGSSupport(platformConfig)) {
 *   // Show AGS checkbox in registration form
 *   // Enable grade passback functionality
 * }
 * ```
 */
export function hasAGSSupport(config: OpenIDConfiguration): boolean {
  return hasAnySupportedScope(config.scopes_supported, LTI_AGS_SCOPES);
}

/**
 * Checks if an LTI platform supports Names and Role Provisioning Services (NRPS).
 * Examines the platform's OpenID configuration for NRPS-related OAuth scopes.
 *
 * @param config - Platform's OpenID Connect configuration from discovery endpoint
 * @returns True if the platform supports any NRPS scopes, false otherwise
 *
 * @example
 * ```typescript
 * if (hasNRPSSupport(platformConfig)) {
 *   // Show NRPS checkbox in registration form
 *   // Enable roster access functionality
 * }
 * ```
 */
export function hasNRPSSupport(config: OpenIDConfiguration): boolean {
  return hasAnySupportedScope(config.scopes_supported, LTI_NRPS_SCOPES);
}

/**
 * Checks if an LTI platform supports Deep Linking for content selection.
 * Examines the platform's LTI configuration for supported message types.
 *
 * @param config - Platform's OpenID Connect configuration from discovery endpoint
 * @returns True if the platform supports LtiDeepLinkingRequest messages, false otherwise
 *
 * @example
 * ```typescript
 * if (hasDeepLinkingSupport(platformConfig)) {
 *   // Show Deep Linking checkbox in registration form
 *   // Enable content selection functionality
 * }
 * ```
 */
export function hasDeepLinkingSupport(config: OpenIDConfiguration): boolean {
  const ltiConfig = config[LTI_CLAIM_PLATFORM_CONFIGURATION];
  return (
    ltiConfig?.messages_supported?.some(
      (msg) => msg.type === LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
    ) ?? false
  );
}

/**
 * Extracts all Assignment and Grade Services (AGS) scopes supported by the platform.
 * Filters the platform's supported scopes to return only AGS-related scope URIs.
 *
 * @param config - Platform's OpenID Connect configuration from discovery endpoint
 * @returns Array of AGS scope URIs supported by the platform (e.g., lineitem, score, result.readonly)
 *
 * @example
 * ```typescript
 * const agsScopes = getAGSScopes(platformConfig);
 * // Returns: [LTI_AGS_SCOPE_LINEITEM, ...]
 * console.log('Available AGS scopes:', agsScopes.join(', '));
 * ```
 */
export function getAGSScopes(config: OpenIDConfiguration): string[] {
  return filterSupportedScopes(config.scopes_supported, LTI_AGS_SCOPES);
}
