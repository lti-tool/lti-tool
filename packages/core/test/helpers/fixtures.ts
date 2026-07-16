import {
  LTI_AGS_SCOPE_SCORE,
  LTI_CLAIM_AGS_ENDPOINT,
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_ROLES,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  LTI_VERSION_1P3P0,
} from '../../src/constants.js';
import type { LTI13JwtPayload } from '../../src/schemas/index.js';

export const createMockLTIPayload = (overrides = {}): Partial<LTI13JwtPayload> => ({
  iss: 'https://platform.example.com',
  aud: 'client123',
  sub: 'user123',
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 300,
  nonce: 'test-nonce',
  given_name: 'Jane',
  family_name: 'Smith',
  name: 'Jane Smith',
  email: 'jane.smith@university.edu',
  [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
  [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
  [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
  [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
  [LTI_CLAIM_CONTEXT]: {
    id: 'course456',
    label: 'MATH201',
    title: 'Advanced Mathematics',
  },
  [LTI_CLAIM_RESOURCE_LINK]: {
    id: 'assignment789',
    title: 'Homework 3',
  },
  [LTI_CLAIM_AGS_ENDPOINT]: {
    lineitem: 'https://platform.example.com/api/ags/lineitem/789',
    lineitems: 'https://platform.example.com/api/ags/lineitems',
    scope: [LTI_AGS_SCOPE_SCORE],
  },
  ...overrides,
});
