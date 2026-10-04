import type { BaseLogger } from 'pino';

import {
  LTI_AGS_SCOPE_LINEITEM,
  LTI_AGS_SCOPE_LINEITEM_READONLY,
  LTI_AGS_SCOPE_RESULT_READONLY,
  LTI_AGS_SCOPE_SCORE,
} from '../constants.js';
import type { LTISession } from '../interfaces/ltiSession.js';
import type { LTIStorage } from '../interfaces/ltiStorage.js';
import type {
  CreateLineItem,
  UpdateLineItem,
} from '../schemas/lti13/ags/lineItem.schema.js';
import type { ScoreSubmission } from '../schemas/lti13/ags/scoreSubmission.schema.js';
import { getValidLaunchConfig } from '../utils/launchConfigValidation.js';
import { ltiServiceFetch } from '../utils/ltiServiceFetch.js';

import type { TokenService } from './token.service.js';

export interface AGSLineItemTargetOptions {
  /** Optional line item URL to read instead of the launch session's default line item. */
  lineItemUrl?: string;
}

export interface AGSGetScoresOptions extends AGSLineItemTargetOptions {
  /** Optional AGS user_id filter for fetching a single user's result. */
  userId?: string;
  /** Optional maximum number of results to request. */
  limit?: number;
}

export interface AGSListLineItemsOptions {
  /** Optional AGS resource_id filter. */
  resourceId?: string;
  /** Optional AGS resource_link_id filter. */
  resourceLinkId?: string;
  /** Optional AGS tag filter. */
  tag?: string;
  /** Optional maximum number of line items to request. */
  limit?: number;
}

/**
 * Assignment and Grade Services (AGS) implementation for LTI 1.3.
 * Provides methods to submit grades and scores back to the platform.
 *
 * @see https://www.imsglobal.org/spec/lti-ags/v2p0
 */
export class AGSService {
  /**
   * Creates a new AGSService instance.
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
   * Submits a grade score to the platform using LTI Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS endpoint configuration
   * @param score - Score submission data including grade value and metadata
   * @returns Promise resolving to the HTTP response from the platform
   * @throws {Error} When AGS is not available for the session or submission fails
   *
   * @example
   * ```typescript
   * await agsService.submitScore(session, {
   *   scoreGiven: 85,
   *   scoreMaximum: 100,
   *   comment: 'Great work!',
   *   activityProgress: 'Completed',
   *   gradingProgress: 'FullyGraded'
   * });
   * ```
   */
  async submitScore(session: LTISession, score: ScoreSubmission): Promise<Response> {
    if (!session.services?.ags?.lineitem) {
      throw new Error('AGS not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_SCORE);

    const scorePayload = {
      userId: score.userId,
      scoreGiven: score.scoreGiven,
      scoreMaximum: score.scoreMaximum,
      comment: score.comment,
      timestamp: score.timestamp || new Date().toISOString(),
      activityProgress: score.activityProgress,
      gradingProgress: score.gradingProgress,
    };

    const agsScoreEndpoint = `${session.services.ags.lineitem}/scores`;
    const response = await ltiServiceFetch(agsScoreEndpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/vnd.ims.lis.v1.score+json',
      },
      body: JSON.stringify(scorePayload),
    });

    await this.validateAGSResponse(response, 'score submission');
    return response;
  }

  /**
   * Retrieves all scores for a specific line item from the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line item endpoint configuration
   * @param options - Optional line item target override and AGS result filters
   * @returns Promise resolving to the HTTP response containing scores data for the line item
   * @throws {Error} When AGS line item service is not available for the session or request fails
   *
   * @example
   * ```typescript
   * const response = await agsService.getScores(session);
   * const scores = await response.json();
   * console.log('All scores for this line item:', scores);
   * ```
   */
  async getScores(
    session: LTISession,
    options: AGSGetScoresOptions = {},
  ): Promise<Response> {
    const lineItemUrl = options.lineItemUrl ?? session.services?.ags?.lineitem;

    if (!lineItemUrl) {
      throw new Error('AGS line item not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_RESULT_READONLY);

    const response = await ltiServiceFetch(this.buildResultsUrl(lineItemUrl, options), {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.ims.lis.v2.resultcontainer+json',
      },
    });

    await this.validateAGSResponse(response, 'get scores');
    return response;
  }

  /**
   * Retrieves line items (gradebook columns) from the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line items endpoint configuration
   * @param options - Optional AGS line item list filters
   * @returns Promise resolving to the HTTP response containing line items data
   * @throws {Error} When AGS line items service is not available for the session or request fails
   *
   * @example
   * ```typescript
   * const response = await agsService.listLineItems(session);
   * const lineItems = await response.json();
   * console.log('Available gradebook columns:', lineItems);
   * ```
   */
  async listLineItems(
    session: LTISession,
    options: AGSListLineItemsOptions = {},
  ): Promise<Response> {
    if (!session.services?.ags?.lineitems) {
      throw new Error('AGS list line items not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_LINEITEM_READONLY);

    const response = await ltiServiceFetch(
      this.buildLineItemsUrl(session.services.ags.lineitems, options),
      {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/vnd.ims.lis.v2.lineitemcontainer+json',
        },
      },
    );

    await this.validateAGSResponse(response, 'list line items');
    return response;
  }

  /**
   * Retrieves a specific line item (gradebook column) from the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line item endpoint configuration
   * @param options - Optional line item target override
   * @returns Promise resolving to the HTTP response containing the line item data
   * @throws {Error} When AGS line item service is not available for the session or request fails
   *
   * @example
   * ```typescript
   * const response = await agsService.getLineItem(session);
   * const lineItem = await response.json();
   * console.log('Line item details:', lineItem);
   * ```
   */
  async getLineItem(
    session: LTISession,
    options: AGSLineItemTargetOptions = {},
  ): Promise<Response> {
    const lineItemUrl = options.lineItemUrl ?? session.services?.ags?.lineitem;

    if (!lineItemUrl) {
      throw new Error('AGS line item not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_LINEITEM_READONLY);

    const response = await ltiServiceFetch(lineItemUrl, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/vnd.ims.lis.v2.lineitem+json',
      },
    });

    await this.validateAGSResponse(response, 'get line item');
    return response;
  }

  /**
   * Creates a new line item (gradebook column) on the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line items endpoint configuration
   * @param createLineItem - Line item data including label, scoreMaximum, and optional metadata
   * @returns Promise resolving to the HTTP response containing the created line item with generated ID
   * @throws {Error} When AGS line item creation service is not available for the session or creation fails
   *
   * @example
   * ```typescript
   * const response = await agsService.createLineItem(session, {
   *   label: 'Quiz 1',
   *   scoreMaximum: 100,
   *   tag: 'quiz',
   *   resourceId: 'quiz-001'
   * });
   * const newLineItem = await response.json();
   * console.log('Created line item:', newLineItem.id);
   * ```
   */
  async createLineItem(
    session: LTISession,
    createLineItem: CreateLineItem,
  ): Promise<Response> {
    if (!session.services?.ags?.lineitems) {
      throw new Error('AGS create line items not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_LINEITEM);

    const response = await ltiServiceFetch(`${session.services.ags.lineitems}`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/vnd.ims.lis.v2.lineitem+json',
      },
      body: JSON.stringify(createLineItem),
    });

    await this.validateAGSResponse(response, 'create line item');
    return response;
  }

  /**
   * Updates an existing line item (gradebook column) on the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line item endpoint configuration
   * @param updateLineItem - Updated line item data including all required fields
   * @returns Promise resolving to the HTTP response containing the updated line item
   * @throws {Error} When AGS line item service is not available for the session or update fails
   *
   * @example
   * ```typescript
   * const response = await agsService.updateLineItem(session, {
   *   label: 'Quiz 1 (Updated)',
   *   scoreMaximum: 100,
   *   tag: 'quiz'
   * });
   * const updatedLineItem = await response.json();
   * ```
   */
  async updateLineItem(
    session: LTISession,
    updateLineItem: UpdateLineItem,
  ): Promise<Response> {
    if (!session.services?.ags?.lineitem) {
      throw new Error('AGS line item not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_LINEITEM);

    const response = await ltiServiceFetch(session.services.ags.lineitem, {
      method: 'PUT',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/vnd.ims.lis.v2.lineitem+json',
      },
      body: JSON.stringify(updateLineItem),
    });

    await this.validateAGSResponse(response, 'update line item');
    return response;
  }

  /**
   * Deletes a line item (gradebook column) from the platform using Assignment and Grade Services.
   *
   * @param session - Active LTI session containing AGS line item endpoint configuration
   * @returns Promise resolving to the HTTP response (typically 204 No Content on success)
   * @throws {Error} When AGS line item service is not available for the session or deletion fails
   *
   * @example
   * ```typescript
   * const response = await agsService.deleteLineItem(session);
   * console.log('Line item deleted successfully');
   * ```
   */
  async deleteLineItem(session: LTISession): Promise<Response> {
    if (!session.services?.ags?.lineitem) {
      throw new Error('AGS line item not available for this session');
    }

    const token = await this.getAGSToken(session, LTI_AGS_SCOPE_LINEITEM);

    const response = await ltiServiceFetch(session.services.ags.lineitem, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`,
      },
    });

    await this.validateAGSResponse(response, 'delete line item');
    return response;
  }

  private async getAGSToken(session: LTISession, scope: string): Promise<string> {
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

  private buildLineItemsUrl(
    lineItemsUrl: string,
    options: AGSListLineItemsOptions,
  ): string {
    const url = new URL(lineItemsUrl);

    if (options.resourceId !== undefined) {
      url.searchParams.set('resource_id', options.resourceId);
    }
    if (options.resourceLinkId !== undefined) {
      url.searchParams.set('resource_link_id', options.resourceLinkId);
    }
    if (options.tag !== undefined) {
      url.searchParams.set('tag', options.tag);
    }
    if (options.limit !== undefined) {
      url.searchParams.set('limit', String(options.limit));
    }

    return url.toString();
  }

  private buildResultsUrl(lineItemUrl: string, options: AGSGetScoresOptions): string {
    const url = new URL(lineItemUrl);
    url.pathname = `${url.pathname.replace(/\/$/, '')}/results`;

    if (options.userId !== undefined) {
      url.searchParams.set('user_id', options.userId);
    }
    if (options.limit !== undefined) {
      url.searchParams.set('limit', String(options.limit));
    }

    return url.toString();
  }

  private async validateAGSResponse(
    response: Response,
    operation: string,
  ): Promise<void> {
    if (!response.ok) {
      const error = await response.json();
      this.logger.error(
        { error, status: response.status, statusText: response.statusText },
        `AGS ${operation} failed`,
      );
      throw new Error(`AGS ${operation} failed: ${response.statusText} ${error}`);
    }
  }
}
