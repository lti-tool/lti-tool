import * as z from 'zod';

import {
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_ROLES,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  LTI_VERSION_1P3P0,
} from '../../../constants.js';

export const CoreLtiClaimsSchema = z.object({
  [LTI_CLAIM_MESSAGE_TYPE]: z.union([
    z.literal(LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST),
    z.literal(LTI_MESSAGE_TYPE_DEEP_LINKING_REQUEST),
  ]),
  [LTI_CLAIM_VERSION]: z.literal(LTI_VERSION_1P3P0),
  [LTI_CLAIM_DEPLOYMENT_ID]: z.string(),
  [LTI_CLAIM_TARGET_LINK_URI]: z.url(),
  [LTI_CLAIM_ROLES]: z.array(z.string()).optional(),
});
