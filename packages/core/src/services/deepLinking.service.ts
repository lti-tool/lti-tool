import { SignJWT } from 'jose';
import type { BaseLogger } from 'pino';

import {
  LTI_CLAIM_DEEP_LINKING_CONTENT_ITEMS,
  LTI_CLAIM_DEEP_LINKING_DATA,
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_DEEP_LINKING_RESPONSE,
  LTI_VERSION_1P3P0,
} from '../constants.js';
import type { LTISession } from '../interfaces/ltiSession.js';
import type { DeepLinkingContentItem } from '../schemas/lti13/deepLinking/contentItem.schema.js';
import { escapeHtml } from '../utils/htmlEscaping.js';

/**
 * Deep Linking service for LTI 1.3.
 * Generates signed JWT responses containing selected content items to return to the platform.
 *
 * @see https://www.imsglobal.org/spec/lti-dl/v2p0
 */
export class DeepLinkingService {
  /**
   * Creates a new DeepLinkingService instance.
   *
   * @param keyPair - RSA key pair for signing client assertion JWTs (must be RS256 compatible)
   * @param logger - Logger instance for debug and error logging
   * @param keyId - Key identifier for JWT header, should match JWKS key ID (defaults to 'main')
   */
  constructor(
    private keyPair: CryptoKeyPair,
    private logger: BaseLogger,
    private keyId = 'main',
  ) {}

  /**
   * Creates a Deep Linking response with selected content items.
   * Generates a signed JWT and returns an HTML form that auto-submits to the platform.
   *
   * @param session - Active LTI session containing Deep Linking configuration
   * @param contentItems - Array of content items selected by the user
   * @returns Promise resolving to an HTML string containing auto-submit form
   * @throws {Error} When Deep Linking is not available for the session
   *
   * @example
   * ```typescript
   * const html = await deepLinkingService.createResponse(session, [
   *   {
   *     type: 'ltiResourceLink',
   *     title: 'Quiz 1',
   *     url: 'https://tool.example.com/quiz/1'
   *   }
   * ]);
   * // Returns HTML form that auto-submits to platform
   * ```
   */
  async createResponse(
    session: LTISession,
    contentItems: DeepLinkingContentItem[],
  ): Promise<string> {
    if (!session.services?.deepLinking) {
      throw new Error('Deep Linking not available for this session');
    }

    this.logger.debug(
      {
        contentItemCount: contentItems.length,
        returnUrl: session.services.deepLinking.returnUrl,
      },
      'Creating Deep Linking response',
    );

    const jwt = await this.createDeepLinkingJWT(session, contentItems);
    return this.generateAutoSubmitForm(session.services.deepLinking.returnUrl, jwt);
  }

  /**
   * Creates a signed JWT containing the Deep Linking response payload.
   *
   * @param session - Active LTI session with Deep Linking configuration
   * @param contentItems - Array of selected content items
   * @returns Promise resolving to a signed JWT string
   */
  private async createDeepLinkingJWT(
    session: LTISession,
    contentItems: DeepLinkingContentItem[],
  ): Promise<string> {
    const deepLinking = session.services!.deepLinking!;

    const payload = {
      iss: session.platform.clientId,
      aud: session.platform.issuer,
      exp: Math.floor(Date.now() / 1000) + 600,
      iat: Math.floor(Date.now() / 1000),
      nonce: crypto.randomUUID(),
      [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_DEEP_LINKING_RESPONSE,
      [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
      [LTI_CLAIM_DEPLOYMENT_ID]: session.platform.deploymentId,
      [LTI_CLAIM_DEEP_LINKING_CONTENT_ITEMS]: contentItems,
      [LTI_CLAIM_DEEP_LINKING_DATA]: deepLinking.data,
    };

    return await new SignJWT(payload)
      .setProtectedHeader({
        alg: 'RS256',
        typ: 'JWT',
        kid: this.keyId,
      })
      .sign(this.keyPair.privateKey);
  }

  /**
   * Generates an HTML form that auto-submits the Deep Linking response to the platform.
   *
   * @param returnUrl - Platform's Deep Linking return URL
   * @param jwt - Signed JWT containing the response
   * @returns HTML string with auto-submit form
   */
  private generateAutoSubmitForm(returnUrl: string, jwt: string): string {
    return `
<!DOCTYPE html>
<html>
<head>
  <title>Returning to platform...</title>
</head>
<body>
  <form id="deepLinkingForm" method="POST" action="${escapeHtml(returnUrl)}">
    <input type="hidden" name="JWT" value="${escapeHtml(jwt)}" />
  </form>
  <script>
    document.getElementById('deepLinkingForm').submit();
  </script>
</body>
</html>`;
  }
}
