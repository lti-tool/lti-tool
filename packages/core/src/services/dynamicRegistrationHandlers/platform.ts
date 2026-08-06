import type { BaseLogger } from 'pino';

import { LTI_AGS_SCOPE_PREFIX } from '../../constants.js';
import {
  RegistrationResponseSchema,
  type OpenIDConfiguration,
  type RegistrationResponse,
} from '../../schemas/index.js';
import { escapeHtml } from '../../utils/htmlEscaping.js';
import {
  getAGSScopes,
  hasAGSSupport,
  hasDeepLinkingSupport,
  hasNRPSSupport,
} from '../../utils/ltiPlatformCapabilities.js';
import { ltiServiceFetch } from '../../utils/ltiServiceFetch.js';

/**
 * Generates a generic dynamic registration form with service selection options.
 * Creates a Bootstrap 5 form that detects available LTI Advantage services from the platform
 * configuration and presents them as selectable checkboxes to the administrator.
 *
 * @param openIdConfiguration - Platform's OpenID Connect configuration containing supported services
 * @param currentPath - Current request path used to build the form submission URL
 * @param sessionToken - Security token for CSRF protection and session validation
 * @returns Complete HTML page with Bootstrap form for service selection
 *
 * @example
 * ```typescript
 * const html = renderDynamicRegistrationForm(
 *   platformConfig,
 *   '/lti/register',
 *   'uuid-session-token'
 * );
 * // Returns HTML form with AGS, NRPS, and Deep Linking options if supported
 * ```
 */
// oxlint-disable-next-line max-lines-per-function
export function renderDynamicRegistrationForm(
  openIdConfiguration: OpenIDConfiguration,
  currentPath: string,
  sessionToken: string,
): string {
  const hasAGS = hasAGSSupport(openIdConfiguration);
  const hasNRPS = hasNRPSSupport(openIdConfiguration);
  const hasDeepLinking = hasDeepLinkingSupport(openIdConfiguration);
  const agsScopes = getAGSScopes(openIdConfiguration);
  // Build complete action from current path
  const completeAction = `${currentPath}/complete`;

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Configure LTI Advantage Settings</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
      </head>
      <body class="container mt-4">
        <form method="POST" action="${escapeHtml(completeAction)}">
          <div class="mb-3">
            <label class="form-label">Available Services</label>
            ${
              hasAGS
                ? `
                  <div class="form-check">
                    <input class="form-check-input" type="checkbox" name="services" value="ags" id="ags" checked>
                    <label class="form-check-label" for="ags">
                      <strong>Assignment and Grade Services (AGS)</strong>
                      <small class="text-muted d-block">Enables automatic grade passback from this tool to your gradebook</small>
                    </label>
                    <div class="mt-2 ms-4">
                      <small class="text-muted">OAuth Scopes that will be requested:</small>
                      <pre class="bg-light p-2 mt-1 small border rounded">${agsScopes.map((scope) => scope.replace(LTI_AGS_SCOPE_PREFIX, '')).join('\n')}</pre>
                    </div>
                  </div>
            `
                : ''
            }
            
            ${
              hasNRPS
                ? `
              <div class="form-check">
                <input class="form-check-input" type="checkbox" name="services" value="nrps" id="nrps" checked>
                <label class="form-check-label" for="nrps">Names and Role Provisioning Services (NRPS)</label>
              </div>
            `
                : ''
            }
            
            ${
              hasDeepLinking
                ? `
              <div class="form-check">
                <input class="form-check-input" type="checkbox" name="services" value="deep_linking" id="deep_linking" checked>
                <label class="form-check-label" for="deep_linking">Deep Linking</label>
              </div>
            `
                : ''
            }
          </div>
          <div class="mb-3">
            <label class="form-label">Required Privacy Settings</label>
            <div class="alert alert-info">
              <small>These privacy settings must be enabled in your LMS for this tool to function properly.</small>
            </div>
            
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="share_name" checked disabled>
              <label class="form-check-label" for="share_name">
                Share launcher's name
                <small class="text-muted d-block">Required for user identification</small>
              </label>
            </div>
            
            <div class="form-check">
              <input class="form-check-input" type="checkbox" id="share_email" checked disabled>
              <label class="form-check-label" for="share_email">
                Share launcher's email
                <small class="text-muted d-block">Required for user communication</small>
              </label>
            </div>
          </div>

          <input type="hidden" name="sessionToken" value="${escapeHtml(sessionToken)}">

          <button type="submit" class="btn btn-primary">Register Tool</button>
        </form>
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
      </body>
    </html>`;
}

/**
 * Submits tool registration payload to a platform's dynamic registration endpoint.
 * Handles the HTTP communication with proper authentication, error handling, and response validation.
 * Validates the registration response against the LTI 1.3 specification schema.
 *
 * @param registrationEndpoint - Platform's registration endpoint URL from OpenID configuration
 * @param registrationPayload - Complete tool registration payload with OAuth and LTI configuration
 * @param logger - Pino logger instance for request/response logging and error tracking
 * @param registrationToken - Optional bearer token for authenticated registration requests
 * @returns Validated registration response containing client credentials and deployment information
 * @throws {Error} When registration request fails or response validation fails
 *
 * @example
 * ```typescript
 * const response = await postRegistrationToPlatform(
 *   'https://platform.example/registration',
 *   registrationPayload,
 *   logger,
 *   'optional-bearer-token'
 * );
 * console.log('Registered with client ID:', response.client_id);
 * ```
 */
export async function postRegistrationToPlatform(
  registrationEndpoint: string,
  registrationPayload: unknown,
  logger: BaseLogger,
  registrationToken?: string,
): Promise<RegistrationResponse> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (registrationToken) {
    headers['Authorization'] = `Bearer ${registrationToken}`;
  }

  const response = await ltiServiceFetch(registrationEndpoint, {
    method: 'POST',
    headers,
    body: JSON.stringify(registrationPayload),
  });

  if (!response.ok) {
    const errorText = await response.json();
    logger.error({ errorText }, 'lti dynamic registration error');
    throw new Error(JSON.stringify(errorText));
  }

  const data = await response.json();
  logger.debug({ data }, 'Registration response');
  const validated = RegistrationResponseSchema.parse(data);
  logger.debug({ validated }, 'Registration response validated');
  return validated;
}
