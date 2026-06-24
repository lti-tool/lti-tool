import * as z from 'zod';

import {
  LTI_CLAIM_AGS_ENDPOINT,
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_CUSTOM,
  LTI_CLAIM_DEEP_LINKING_SETTINGS,
  LTI_CLAIM_LAUNCH_PRESENTATION,
  LTI_CLAIM_LIS,
  LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_TOOL_PLATFORM,
} from '../../constants.js';

import { BaseJwtClaimsSchema } from './claims/baseJwtClaims.schema.js';
import { ContextSchema, ResourceLinkSchema } from './claims/contextClaims.schema.js';
import { CoreLtiClaimsSchema } from './claims/coreLtiClaims.schema.js';
import {
  LaunchPresentationSchema,
  LisSchema,
  ToolPlatformSchema,
} from './claims/platformClaims.schema.js';
import { PrivacyClaimsSchema } from './claims/privacyClaims.schema.js';
import {
  AgsEndpointSchema,
  DeepLinkingSettingsSchema,
  NrpsServiceSchema,
} from './claims/serviceClaims.schema.js';

export const LTI13JwtPayloadSchema = BaseJwtClaimsSchema.extend(PrivacyClaimsSchema.shape)
  .extend(CoreLtiClaimsSchema.shape)
  .extend({
    [LTI_CLAIM_RESOURCE_LINK]: ResourceLinkSchema,
    [LTI_CLAIM_CONTEXT]: ContextSchema,
    [LTI_CLAIM_TOOL_PLATFORM]: ToolPlatformSchema,
    [LTI_CLAIM_LIS]: LisSchema,
    [LTI_CLAIM_LAUNCH_PRESENTATION]: LaunchPresentationSchema,
    [LTI_CLAIM_CUSTOM]: z.record(z.string(), z.string()).optional(),
    [LTI_CLAIM_AGS_ENDPOINT]: AgsEndpointSchema,
    [LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE]: NrpsServiceSchema,
    [LTI_CLAIM_DEEP_LINKING_SETTINGS]: DeepLinkingSettingsSchema,
  });

export type LTI13JwtPayload = z.infer<typeof LTI13JwtPayloadSchema>;
