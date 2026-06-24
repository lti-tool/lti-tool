import {
  LTI_CLAIM_PLATFORM_CONFIGURATION,
  LTI_CLAIM_TOOL_CONFIGURATION,
  LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
} from '../constants.js';
import type {
  CanvasDynamicRegistrationConfig,
  DynamicRegistrationConfig,
} from '../interfaces/ltiConfig.js';
import type { LTIMessage } from '../schemas/lti13/dynamicRegistration/ltiMessages.schema.js';
import type { OpenIDConfiguration } from '../schemas/lti13/dynamicRegistration/openIDConfiguration.schema.js';
import type { ToolRegistrationPayload } from '../schemas/lti13/dynamicRegistration/toolRegistrationPayload.schema.js';

interface DynamicRegistrationMessageContext {
  selectedServices: string[];
  deepLinkingUri: string;
  launchUri: string;
  toolName: string;
  registrationConfig: DynamicRegistrationConfig;
}

interface DynamicRegistrationPayloadContext {
  payload: ToolRegistrationPayload;
  registrationConfig: DynamicRegistrationConfig;
}

interface DynamicRegistrationProfile {
  matches(openIdConfiguration: OpenIDConfiguration): boolean;
  buildMessages(context: DynamicRegistrationMessageContext): LTIMessage[];
  transformPayload?(context: DynamicRegistrationPayloadContext): ToolRegistrationPayload;
}

function buildDefaultDeepLinkingMessage(
  deepLinkingUri: string,
  toolName: string,
): LTIMessage {
  return {
    type: LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
    target_link_uri: deepLinkingUri,
    label: toolName,
    placements: ['editor_button' as const],
    supported_types: ['ltiResourceLink' as const],
  };
}

function buildCanvasDeepLinkingMessages(
  deepLinkingUri: string,
  toolName: string,
  placements: string[],
): LTIMessage[] {
  return placements.map((placement) => ({
    type: LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
    target_link_uri: deepLinkingUri,
    label: toolName,
    placements: [placement],
    supported_types: ['ltiResourceLink'],
  }));
}

function getCanvasConfig(
  registrationConfig: DynamicRegistrationConfig,
): CanvasDynamicRegistrationConfig | undefined {
  return registrationConfig.platforms?.canvas;
}

const defaultDynamicRegistrationProfile: DynamicRegistrationProfile = {
  matches: () => true,
  buildMessages({ selectedServices, deepLinkingUri, toolName }) {
    const messages: LTIMessage[] = [{ type: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST }];

    if (selectedServices.includes('deep_linking')) {
      messages.push(buildDefaultDeepLinkingMessage(deepLinkingUri, toolName));
    }

    return messages;
  },
};

const canvasDynamicRegistrationProfile: DynamicRegistrationProfile = {
  matches(openIdConfiguration) {
    return (
      openIdConfiguration[
        LTI_CLAIM_PLATFORM_CONFIGURATION
      ].product_family_code.toLowerCase() === 'canvas'
    );
  },
  buildMessages({
    selectedServices,
    deepLinkingUri,
    launchUri,
    toolName,
    registrationConfig,
  }) {
    const canvasConfig = getCanvasConfig(registrationConfig);
    const messages: LTIMessage[] = [
      {
        type: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        ...(canvasConfig?.resourceLinkPlacements?.length
          ? {
              label: toolName,
              target_link_uri: launchUri,
              placements: canvasConfig.resourceLinkPlacements,
            }
          : {}),
      },
    ];

    if (selectedServices.includes('deep_linking')) {
      messages.push(
        ...buildCanvasDeepLinkingMessages(
          deepLinkingUri,
          toolName,
          canvasConfig?.deepLinkPlacements ?? [
            'editor_button',
            'module_menu_modal',
            'assignment_selection',
            'module_index_menu_modal',
            'link_selection',
          ],
        ),
      );
    }

    return messages;
  },
  transformPayload({ payload, registrationConfig }) {
    const canvasConfig = getCanvasConfig(registrationConfig);
    if (!canvasConfig) {
      return payload;
    }

    return {
      ...payload,
      ...(canvasConfig.clientUri ? { client_uri: canvasConfig.clientUri } : {}),
      [LTI_CLAIM_TOOL_CONFIGURATION]: {
        ...payload[LTI_CLAIM_TOOL_CONFIGURATION],
        ...(canvasConfig.secondaryDomains?.length
          ? { secondary_domains: canvasConfig.secondaryDomains }
          : {}),
        ...(canvasConfig.privacyLevel
          ? {
              'https://canvas.instructure.com/lti/privacy_level':
                canvasConfig.privacyLevel,
            }
          : {}),
        ...(canvasConfig.toolId
          ? { 'https://canvas.instructure.com/lti/tool_id': canvasConfig.toolId }
          : {}),
        ...(canvasConfig.vendor
          ? { 'https://canvas.instructure.com/lti/vendor': canvasConfig.vendor }
          : {}),
      },
    };
  },
};

const dynamicRegistrationProfiles: DynamicRegistrationProfile[] = [
  canvasDynamicRegistrationProfile,
];

export function buildDynamicRegistrationMessages(
  openIdConfiguration: OpenIDConfiguration,
  context: DynamicRegistrationMessageContext,
): LTIMessage[] {
  const profile = resolveDynamicRegistrationProfile(openIdConfiguration);

  return profile.buildMessages(context);
}

export function transformDynamicRegistrationPayload(
  openIdConfiguration: OpenIDConfiguration,
  context: DynamicRegistrationPayloadContext,
): ToolRegistrationPayload {
  const profile = resolveDynamicRegistrationProfile(openIdConfiguration);
  return profile.transformPayload?.(context) ?? context.payload;
}

function resolveDynamicRegistrationProfile(
  openIdConfiguration: OpenIDConfiguration,
): DynamicRegistrationProfile {
  const profile =
    dynamicRegistrationProfiles.find((candidate) =>
      candidate.matches(openIdConfiguration),
    ) ?? defaultDynamicRegistrationProfile;

  return profile;
}
