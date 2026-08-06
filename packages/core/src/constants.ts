export const LTI_VERSION_1P3P0 = '1.3.0' as const;

export const LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST = 'LtiResourceLinkRequest' as const;
export const LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST = 'LtiDeepLinkingRequest' as const;
export const LTI_MESSAGE_TYPE_DEEP_LINKING_RESPONSE = 'LtiDeepLinkingResponse' as const;

export const LTI_CLAIM_MESSAGE_TYPE =
  'https://purl.imsglobal.org/spec/lti/claim/message_type' as const;
export const LTI_CLAIM_VERSION =
  'https://purl.imsglobal.org/spec/lti/claim/version' as const;
export const LTI_CLAIM_DEPLOYMENT_ID =
  'https://purl.imsglobal.org/spec/lti/claim/deployment_id' as const;
export const LTI_CLAIM_TARGET_LINK_URI =
  'https://purl.imsglobal.org/spec/lti/claim/target_link_uri' as const;
export const LTI_CLAIM_ROLES = 'https://purl.imsglobal.org/spec/lti/claim/roles' as const;
export const LTI_CLAIM_RESOURCE_LINK =
  'https://purl.imsglobal.org/spec/lti/claim/resource_link' as const;
export const LTI_CLAIM_CONTEXT =
  'https://purl.imsglobal.org/spec/lti/claim/context' as const;
export const LTI_CLAIM_TOOL_PLATFORM =
  'https://purl.imsglobal.org/spec/lti/claim/tool_platform' as const;
export const LTI_CLAIM_LIS = 'https://purl.imsglobal.org/spec/lti/claim/lis' as const;
export const LTI_CLAIM_LAUNCH_PRESENTATION =
  'https://purl.imsglobal.org/spec/lti/claim/launch_presentation' as const;
export const LTI_CLAIM_CUSTOM =
  'https://purl.imsglobal.org/spec/lti/claim/custom' as const;

export const LTI_CLAIM_AGS_ENDPOINT =
  'https://purl.imsglobal.org/spec/lti-ags/claim/endpoint' as const;
export const LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE =
  'https://purl.imsglobal.org/spec/lti-nrps/claim/namesroleservice' as const;
export const LTI_CLAIM_DEEP_LINKING_SETTINGS =
  'https://purl.imsglobal.org/spec/lti-dl/claim/deep_linking_settings' as const;
export const LTI_CLAIM_DEEP_LINKING_CONTENT_ITEMS =
  'https://purl.imsglobal.org/spec/lti-dl/claim/content_items' as const;
export const LTI_CLAIM_DEEP_LINKING_DATA =
  'https://purl.imsglobal.org/spec/lti-dl/claim/data' as const;

export const LTI_CLAIM_PLATFORM_CONFIGURATION =
  'https://purl.imsglobal.org/spec/lti-platform-configuration' as const;
export const LTI_CLAIM_TOOL_CONFIGURATION =
  'https://purl.imsglobal.org/spec/lti-tool-configuration' as const;

export const LTI_AGS_SCOPE_PREFIX =
  'https://purl.imsglobal.org/spec/lti-ags/scope/' as const;
export const LTI_AGS_SCOPE_LINEITEM =
  'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem' as const;
export const LTI_AGS_SCOPE_LINEITEM_READONLY =
  'https://purl.imsglobal.org/spec/lti-ags/scope/lineitem.readonly' as const;
export const LTI_AGS_SCOPE_RESULT_READONLY =
  'https://purl.imsglobal.org/spec/lti-ags/scope/result.readonly' as const;
export const LTI_AGS_SCOPE_SCORE =
  'https://purl.imsglobal.org/spec/lti-ags/scope/score' as const;
export const LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY =
  'https://purl.imsglobal.org/spec/lti-nrps/scope/contextmembership.readonly' as const;

/** All standard LTI 1.3 Assignment and Grade Services OAuth scopes. */
export const LTI_AGS_SCOPES = [
  LTI_AGS_SCOPE_LINEITEM,
  LTI_AGS_SCOPE_LINEITEM_READONLY,
  LTI_AGS_SCOPE_RESULT_READONLY,
  LTI_AGS_SCOPE_SCORE,
] as const;

/** All standard LTI 1.3 Names and Role Provisioning Services OAuth scopes. */
export const LTI_NRPS_SCOPES = [LTI_NRPS_SCOPE_CONTEXT_MEMBERSHIP_READONLY] as const;
