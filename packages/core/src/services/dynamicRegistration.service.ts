import type { BaseLogger } from 'pino';

import {
  LTI_AGS_SCOPE_LINEITEM,
  LTI_AGS_SCOPE_RESULT_READONLY,
  LTI_AGS_SCOPE_SCORE,
  LTI_CLAIM_TOOL_CONFIGURATION,
  LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY,
} from '../constants.js';
import type { DynamicRegistrationConfig } from '../interfaces/ltiConfig.js';
import type { LTIDynamicRegistrationSession } from '../interfaces/ltiDynamicRegistrationSession.js';
import type { LTIStorage } from '../interfaces/ltiStorage.js';
import type { DynamicRegistrationForm } from '../schemas/lti13/dynamicRegistration/ltiDynamicRegistration.schema.js';
import {
  type OpenIDConfiguration,
  openIDConfigurationSchema,
} from '../schemas/lti13/dynamicRegistration/openIDConfiguration.schema.js';
import type { RegistrationRequest } from '../schemas/lti13/dynamicRegistration/registrationRequest.schema.js';
import type { RegistrationResponse } from '../schemas/lti13/dynamicRegistration/registrationResponse.schema.js';
import type { ToolRegistrationPayload } from '../schemas/lti13/dynamicRegistration/toolRegistrationPayload.schema.js';
import { escapeHtml } from '../utils/htmlEscaping.js';
import { ltiServiceFetch } from '../utils/ltiServiceFetch.js';

import {
  postRegistrationToPlatform,
  renderDynamicRegistrationForm,
} from './dynamicRegistrationHandlers/platform.js';
import {
  buildDynamicRegistrationMessages,
  transformDynamicRegistrationPayload,
} from './dynamicRegistrationProfiles.js';

/**
 * Service for handling LTI 1.3 dynamic registration workflows.
 *
 * Provides a complete implementation of the LTI 1.3 Dynamic Registration specification,
 * enabling tools to automatically register with LTI platforms without manual configuration.
 * Handles the full registration lifecycle from initiation to completion with security validation.
 *
 * ## Key Features
 * - **Platform Discovery**: Fetches and validates OpenID Connect configuration from LTI platforms
 * - **Security Validation**: Enforces hostname matching and session-based CSRF protection
 * - **Platform Profiles**: Uses a generic registration flow with targeted platform-specific message overrides only where needed
 * - **Service Selection**: Allows administrators to choose which LTI Advantage services to enable (AGS, NRPS, Deep Linking)
 * - **Automatic Storage**: Persists client and deployment configurations for future launches
 *
 * ## Registration Flow
 * 1. **Initiation**: Platform redirects to tool with registration request
 * 2. **Discovery**: Tool fetches platform's OpenID Connect configuration
 * 3. **Form Generation**: Tool presents service selection form to administrator
 * 4. **Registration**: Tool submits registration payload to platform
 * 5. **Storage**: Tool stores received client credentials and deployment information
 *
 * ## Security Features
 * - Session-based registration with 15-minute expiration
 * - CSRF protection via secure session tokens
 * - Hostname validation between OIDC endpoint and issuer
 * - One-time session consumption to prevent replay attacks
 *
 * @example
 * ```typescript
 * const service = new DynamicRegistrationService(
 *   storage,
 *   dynamicRegistrationConfig,
 *   logger
 * );
 *
 * // Initiate registration
 * const formHtml = await service.initiateDynamicRegistration(request, '/lti/register');
 *
 * // Complete registration
 * const successHtml = await service.completeDynamicRegistration(formData);
 * ```
 *
 * @see https://www.imsglobal.org/spec/lti-dr/v1p0 LTI 1.3 Dynamic Registration specification
 */
export class DynamicRegistrationService {
  /**
   * Creates a new DynamicRegistrationService instance.
   *
   * @param storage - Storage adapter for persisting client and deployment configurations
   * @param dynamicRegistrationConfig - Tool configuration including URLs and service settings
   * @param logger - Logger instance for debug and error logging
   */
  constructor(
    private storage: LTIStorage,
    private dynamicRegistrationConfig: DynamicRegistrationConfig,
    private logger: BaseLogger,
  ) {}

  /**
   * Fetches and validates the OpenID Connect configuration from an LTI platform during dynamic registration.
   * Validates that the OIDC endpoint and issuer have matching hostnames for security.
   *
   * @param registrationRequest - Registration request containing openid_configuration URL and optional registration_token
   * @returns Validated OpenID configuration with platform endpoints and supported features
   * @throws {Error} When the configuration fetch fails, validation fails, or hostname mismatch detected
   */
  async fetchPlatformConfiguration(
    registrationRequest: RegistrationRequest,
  ): Promise<OpenIDConfiguration> {
    const { openid_configuration, registration_token } = registrationRequest;
    const response = await ltiServiceFetch(openid_configuration, {
      method: 'GET',
      headers: {
        // only include registration token if it was provided
        ...(registration_token && { Authorization: `Bearer ${registration_token}` }),
        Accept: 'application/json',
      },
    });

    await this.validateDynamicRegistrationResponse(
      response,
      'validateRegistrationRequest',
    );

    const data = await response.json();
    const openIdConfiguration = openIDConfigurationSchema.parse(data);
    this.logger.debug({ openIdConfiguration });

    // validate that the endpoint and issuer have the same hostname
    const oidcEndpoint = new URL(openid_configuration);
    const { issuer } = openIdConfiguration;
    const issuerEndpoint = new URL(issuer);
    if (oidcEndpoint.hostname !== issuerEndpoint.hostname) {
      const errorMessage = `OIDC endpoint and issuer in OIDC payload do not match, cannot continue. OIDC endpoint: ${oidcEndpoint} issuer endpoint: ${issuerEndpoint}`;
      this.logger.error(errorMessage);
      throw new Error(errorMessage);
    }

    // good to continue!
    return openIdConfiguration;
  }

  /**
   * Initiates LTI 1.3 dynamic registration by fetching platform configuration and generating a registration form.
   * Creates a temporary session and returns HTML form for service selection.
   *
   * @param registrationRequest - Registration request containing openid_configuration URL and optional registration_token
   * @param requestPath - Current request path used to build form action URLs
   * @returns HTML form for service selection and registration completion
   * @throws {Error} When platform configuration fetch fails or session creation fails
   */
  async initiateDynamicRegistration(
    registrationRequest: RegistrationRequest,
    requestPath: string,
  ): Promise<string> {
    // 1. Validate request
    const openIdConfiguration =
      await this.fetchPlatformConfiguration(registrationRequest);

    // 2. generate and store session
    const sessionToken = crypto.randomUUID();
    await this.storage.setRegistrationSession(sessionToken, {
      openIdConfiguration,
      registrationToken: registrationRequest.registration_token,
      expiresAt: Date.now() + 15 * 60 * 1000, // 15 minutes
    });

    // 3. build registration form
    return renderDynamicRegistrationForm(openIdConfiguration, requestPath, sessionToken);
  }

  /**
   * Completes LTI 1.3 dynamic registration by processing form submission and storing client configuration.
   * Validates session, registers with platform, stores client/deployment data, and returns success page.
   *
   * @param dynamicRegistrationForm - Validated form data containing selected services and session token
   * @returns HTML success page with registration details and close button
   * @throws {Error} When session is invalid, registration fails, or storage operations fail
   */
  async completeDynamicRegistration(
    dynamicRegistrationForm: DynamicRegistrationForm,
  ): Promise<string> {
    // 1. Verify session token
    const session = await this.verifyRegistrationSession(
      dynamicRegistrationForm.sessionToken,
    );
    if (!session) {
      throw new Error('Invalid or expired session');
    }

    // 1. build payload
    const toolRegistrationPayload = this.buildRegistrationPayload(
      dynamicRegistrationForm.services ?? [],
      session.openIdConfiguration,
    );

    // 2. Post registration request to the platform
    const registrationResponse = await postRegistrationToPlatform(
      session.openIdConfiguration.registration_endpoint,
      toolRegistrationPayload,
      this.logger,
      session.registrationToken,
    );

    // 3. save to storage
    const clientId = await this.storage.addClient({
      name: registrationResponse.client_name,
      clientId: registrationResponse.client_id,
      iss: session.openIdConfiguration.issuer,
      jwksUrl: session.openIdConfiguration.jwks_uri,
      authUrl: session.openIdConfiguration.authorization_endpoint,
      tokenUrl: session.openIdConfiguration.token_endpoint,
    });

    const ltiToolConfig = registrationResponse[LTI_CLAIM_TOOL_CONFIGURATION];
    if (ltiToolConfig.deployment_id) {
      await this.storage.addDeployment(clientId, {
        deploymentId: ltiToolConfig.deployment_id,
        name: 'Default Deployment via dynamic registration provided deployment id',
      });
    } else {
      // platform doesn't use a deployment id (canvas for example) - create default
      await this.storage.addDeployment(clientId, {
        deploymentId: 'default',
        name: 'Default Deployment (Canvas-style)',
      });
    }

    // 4. return success
    const successHtml = this.getRegistrationSuccessHtml(registrationResponse);
    return successHtml;
  }

  /**
   * Verifies and consumes a registration session token for security validation.
   * Retrieves the session data and immediately deletes it to prevent replay attacks.
   *
   * @param sessionToken - UUID session token from the registration form
   * @returns Session data if valid and not expired, undefined otherwise
   */
  async verifyRegistrationSession(
    sessionToken: string,
  ): Promise<LTIDynamicRegistrationSession | undefined> {
    const session = await this.storage.getRegistrationSession(sessionToken);
    if (session) {
      await this.storage.deleteRegistrationSession(sessionToken);
    }
    return session;
  }

  /**
   * Builds array of OAuth scopes based on selected LTI services during registration.
   * Maps service selections to their corresponding LTI Advantage scope URIs.
   *
   * @param selectedServices - Array of service names selected by administrator ('ags', 'nrps', etc.)
   * @returns Array of OAuth scope URIs to request from the platform
   */
  private buildScopes(selectedServices: string[]): string[] {
    const scopes = [];

    if (selectedServices?.includes('ags')) {
      scopes.push(
        LTI_AGS_SCOPE_LINEITEM,
        LTI_AGS_SCOPE_RESULT_READONLY,
        LTI_AGS_SCOPE_SCORE,
      );
    }

    if (selectedServices?.includes('nrps')) {
      scopes.push(LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY);
    }

    return scopes;
  }

  /**
   * Constructs the complete tool registration payload for platform submission.
   * Combines tool configuration, selected services, and OAuth parameters into LTI 1.3 registration format.
   *
   * @param selectedServices - Array of service names selected by administrator
   * @param openIdConfiguration - OpenID configuration used to select any platform-specific profile overrides
   * @returns Complete registration payload ready for platform submission
   */
  private buildRegistrationPayload(
    selectedServices: string[],
    openIdConfiguration: OpenIDConfiguration,
  ): ToolRegistrationPayload {
    const config = this.dynamicRegistrationConfig;

    const deepLinkingUri = config.deepLinkingUri || `${config.url}/lti/deep-linking`;
    const jwksUri = config.jwksUri || `${config.url}/lti/jwks`;
    const launchUri = config.launchUri || `${config.url}/lti/launch`;
    const loginUri = config.loginUri || `${config.url}/lti/login`;

    const messages = buildDynamicRegistrationMessages(openIdConfiguration, {
      selectedServices,
      deepLinkingUri,
      launchUri,
      toolName: config.name,
      registrationConfig: config,
    });
    const scopes = this.buildScopes(selectedServices);

    return transformDynamicRegistrationPayload(openIdConfiguration, {
      payload: {
        application_type: 'web',
        response_types: ['id_token'],
        grant_types: ['implicit', 'client_credentials'],
        initiate_login_uri: loginUri,
        redirect_uris: [config.url, launchUri, ...(config.redirectUris || [])],
        client_name: config.name,
        jwks_uri: jwksUri,
        logo_uri: config.logo,
        scope: scopes.join(' '),
        token_endpoint_auth_method: 'private_key_jwt',
        [LTI_CLAIM_TOOL_CONFIGURATION]: {
          domain: new URL(config.url).hostname,
          description: config.description,
          target_link_uri: config.url,
          claims: ['iss', 'sub', 'name', 'email'],
          messages,
        },
      },
      registrationConfig: config,
    });
  }

  private async validateDynamicRegistrationResponse(
    response: Response,
    operation: string,
  ): Promise<void> {
    if (!response.ok) {
      const error = await response.json();
      this.logger.error(
        { error, status: response.status, statusText: response.statusText },
        `Dynamic Registration ${operation} failed`,
      );
      throw new Error(
        `Dynamic Registration ${operation} failed: ${response.statusText} ${error}`,
      );
    }
  }

  private getRegistrationSuccessHtml(registrationResponse: RegistrationResponse): string {
    return `
  <!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Registration Complete</title>
      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-sRIl4kxILFvY47J16cr9ZwB07vP4J8+LH7qKQnuqkuIAvNWLzeN8tE5YBujZqJLB" crossorigin="anonymous">
    </head>
    <body class="container mt-4">
      <div class="alert alert-success" role="alert">
        <h4 class="alert-heading">Registration Successful!</h4>
        <p>Your LTI tool has been successfully registered with the platform.</p>
        <hr>
        <p class="mb-0">You can now close this window and return to your LMS.</p>
      </div>
      
      <div class="card">
        <div class="card-header">
          <h5 class="card-title mb-0">Registration Details</h5>
        </div>
        <div class="card-body">
          <dl class="row">
            <dt class="col-sm-3">Tool Name:</dt>
            <dd class="col-sm-9">${escapeHtml(registrationResponse.client_name)}</dd>
            <dt class="col-sm-3">Client ID:</dt>
            <dd class="col-sm-9"><code>${escapeHtml(registrationResponse.client_id)}</code></dd>
            <dt class="col-sm-3">Deployment ID:</dt>
            <dd class="col-sm-9"><code>${escapeHtml(registrationResponse[LTI_CLAIM_TOOL_CONFIGURATION].deployment_id || 'default')}</code></dd>
          </dl>
        </div>
      </div>
      
      <div class="mt-4 text-center">
        <button type="button" class="btn btn-primary btn-lg" onclick="closeWindow()">
          Close Window
        </button>
      </div>
      
      <script>
        function closeWindow() {
          (window.opener || window.parent).postMessage({subject:'org.imsglobal.lti.close'}, '*');
        }
      </script>
      <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js" integrity="sha384-FKyoEForCGlyvwx9Hj09JcYn3nv7wiPVlz7YYwJrWVcXK/BmnVDxM+D2scQbITxI" crossorigin="anonymous"></script>
    </body>
  </html>`;
  }
}
