import type { BaseLogger } from 'pino';

import { LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY } from '../constants.js';
import type { LTISession } from '../interfaces/ltiSession.js';
import type { LTIStorage } from '../interfaces/ltiStorage.js';
import { getValidLaunchConfig } from '../utils/launchConfigValidation.js';
import { ltiServiceFetch } from '../utils/ltiServiceFetch.js';

import type { TokenService } from './token.service.js';

/**
 * Names and Role Provisioning Services (NRPS) implementation for LTI 1.3.
 * Provides methods to retrieve course membership and user information from the platform.
 *
 * @see https://www.imsglobal.org/spec/lti-nrps/v2p0
 */
export class NRPSService {
  /**
   * Creates a new NRPSService instance.
   *
   * @param tokenService - Token service for obtaining OAuth2 bearer tokens
   * @param storage - Storage adapter for retrieving launch configurations
   * @param logger - Logger instance for debug and error logging
   */
  constructor(
    private tokenService: TokenService,
    private storage: LTIStorage,
    private logger: BaseLogger,
  ) {}

  /**
   * Retrieves all members (users) in the current course/context from the platform.
   * Returns raw response that should be parsed by the calling service.
   *
   * @param session - Active LTI session containing NRPS service endpoints
   * @returns Promise resolving to the HTTP response containing membership data
   * @throws {Error} When NRPS is not available for this session or request fails
   *
   * @example
   * ```typescript
   * const response = await nrpsService.getMembers(session);
   * const data = await response.json();
   * console.log('Course members:', data.members);
   * ```
   */
  async getMembers(session: LTISession): Promise<Response> {
    if (!session.services?.nrps?.membershipUrl) {
      throw new Error('NRPS not available for this session');
    }

    const token = await this.getNRPSToken(
      session,
      LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY,
    );

    const response = await ltiServiceFetch(session.services.nrps.membershipUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.ims.lti-nrps.v2.membershipcontainer+json',
      },
    });

    await this.validateNRPSResponse(response, 'get members');
    return response;
  }

  private async getNRPSToken(session: LTISession, scope: string): Promise<string> {
    const launchConfig = await getValidLaunchConfig(
      this.storage,
      session.platform.issuer,
      session.platform.clientId,
      session.platform.deploymentId,
    );

    return this.tokenService.getBearerToken(
      session.platform.clientId,
      launchConfig.tokenUrl,
      scope,
    );
  }

  private async validateNRPSResponse(
    response: Response,
    operation: string,
  ): Promise<void> {
    if (!response.ok) {
      const error = await response.json();
      this.logger.error(
        { error, status: response.status, statusText: response.statusText },
        `NRPS ${operation} failed`,
      );
      throw new Error(`NRPS ${operation} failed: ${response.statusText} ${error}`);
    }
  }
}
