import { describe, expect, it } from 'vitest';

import {
  LTI_CLAIM_AGS_ENDPOINT,
  LTI_CLAIM_CONTEXT,
  LTI_CLAIM_CUSTOM,
  LTI_CLAIM_DEEP_LINKING_SETTINGS,
  LTI_CLAIM_DEPLOYMENT_ID,
  LTI_CLAIM_LAUNCH_PRESENTATION,
  LTI_CLAIM_LIS,
  LTI_CLAIM_MESSAGE_TYPE,
  LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE,
  LTI_CLAIM_PLATFORM_CONFIGURATION,
  LTI_CLAIM_RESOURCE_LINK,
  LTI_CLAIM_ROLES,
  LTI_CLAIM_TARGET_LINK_URI,
  LTI_CLAIM_TOOL_CONFIGURATION,
  LTI_CLAIM_TOOL_PLATFORM,
  LTI_CLAIM_VERSION,
  LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
  LTI_VERSION_1P3P0,
} from '../src/index.js';
import {
  DynamicRegistrationFormSchema,
  HandleLoginParamsSchema,
  LTI13JwtPayloadSchema,
  LTI13LaunchSchema,
  LTI13LoginSchema,
  SessionIdSchema,
  VerifyLaunchParamsSchema,
} from '../src/schemas/index.js';
import { LineItemSchema } from '../src/schemas/lti13/ags/lineItem.schema.js';
import { ResultSchema } from '../src/schemas/lti13/ags/result.schema.js';
import { ScoreSubmissionSchema } from '../src/schemas/lti13/ags/scoreSubmission.schema.js';
import { CoreLtiClaimsSchema } from '../src/schemas/lti13/claims/coreLtiClaims.schema.js';
import { openIDConfigurationSchema } from '../src/schemas/lti13/dynamicRegistration/openIDConfiguration.schema.js';
import { RegistrationResponseSchema } from '../src/schemas/lti13/dynamicRegistration/registrationResponse.schema.js';
import { ToolRegistrationPayloadSchema } from '../src/schemas/lti13/dynamicRegistration/toolRegistrationPayload.schema.js';
import { NRPSContextMembershipResponseSchema } from '../src/schemas/lti13/nrps/contextMembership.schema.js';

describe('Schema Validation Tests', () => {
  describe('LTI constants', () => {
    it('uses exported LTI constants as schema property keys', () => {
      expect(Object.keys(CoreLtiClaimsSchema.shape).sort()).toEqual(
        [
          LTI_CLAIM_DEPLOYMENT_ID,
          LTI_CLAIM_MESSAGE_TYPE,
          LTI_CLAIM_ROLES,
          LTI_CLAIM_TARGET_LINK_URI,
          LTI_CLAIM_VERSION,
        ].sort(),
      );

      const extendedClaimKeys = [
        LTI_CLAIM_RESOURCE_LINK,
        LTI_CLAIM_CONTEXT,
        LTI_CLAIM_TOOL_PLATFORM,
        LTI_CLAIM_LIS,
        LTI_CLAIM_LAUNCH_PRESENTATION,
        LTI_CLAIM_CUSTOM,
        LTI_CLAIM_AGS_ENDPOINT,
        LTI_CLAIM_NRPS_NAMES_ROLE_SERVICE,
        LTI_CLAIM_DEEP_LINKING_SETTINGS,
      ];
      for (const key of extendedClaimKeys) {
        expect(LTI13JwtPayloadSchema.shape).toHaveProperty(key);
      }

      expect(openIDConfigurationSchema.shape).toHaveProperty(
        LTI_CLAIM_PLATFORM_CONFIGURATION,
      );
      expect(ToolRegistrationPayloadSchema.shape).toHaveProperty(
        LTI_CLAIM_TOOL_CONFIGURATION,
      );
      expect(RegistrationResponseSchema.shape).toHaveProperty(
        LTI_CLAIM_TOOL_CONFIGURATION,
      );
    });

    it('accepts exported claim constants as LTI payload property names', () => {
      const validPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
        [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
      };

      expect(() => LTI13JwtPayloadSchema.parse(validPayload)).not.toThrow();
    });
  });

  describe('LTI13LoginSchema', () => {
    it('validates valid login parameters', () => {
      const validLogin = {
        iss: 'https://platform.example.com',
        login_hint: 'user123',
        target_link_uri: 'https://tool.example.com/content',
        client_id: 'client123',
        lti_deployment_id: 'deployment1',
        lti_message_hint: 'hint123',
      };

      expect(() => LTI13LoginSchema.parse(validLogin)).not.toThrow();
    });

    it('rejects empty required strings', () => {
      const invalidLogin = {
        iss: '',
        login_hint: 'user123',
        target_link_uri: 'https://tool.example.com/content',
        client_id: 'client123',
        lti_deployment_id: 'deployment1',
      };

      expect(() => LTI13LoginSchema.parse(invalidLogin)).toThrow();
    });

    it('rejects invalid URLs', () => {
      const invalidLogin = {
        iss: 'https://platform.example.com',
        login_hint: 'user123',
        target_link_uri: 'not-a-url',
        client_id: 'client123',
        lti_deployment_id: 'deployment1',
      };

      expect(() => LTI13LoginSchema.parse(invalidLogin)).toThrow();
    });

    it('rejects missing required fields', () => {
      const incompleteLogin = {
        iss: 'https://platform.example.com',
        login_hint: 'user123',
        // missing target_link_uri, client_id, lti_deployment_id
      };

      expect(() => LTI13LoginSchema.parse(incompleteLogin)).toThrow();
    });
  });

  describe('AGS extension fields', () => {
    it('accepts standard AGS line item fields added by platforms', () => {
      const parsed = LineItemSchema.parse({
        id: 'https://platform.example.com/ags/lineitems/123',
        scoreMaximum: 100,
        label: 'Midterm',
        gradesReleased: true,
      });

      expect(parsed.gradesReleased).toBe(true);
    });

    it('accepts standard AGS result fields and empty result values', () => {
      const parsed = ResultSchema.parse({
        id: 'result-1',
        scoreOf: 'https://platform.example.com/ags/lineitems/123',
        userId: 'learner-1',
        resultScore: null,
        scoringUserId: 'instructor-1',
        comment: null,
      });

      expect(parsed.resultScore).toBeNull();
      expect(parsed.scoringUserId).toBe('instructor-1');
      expect(parsed.comment).toBeNull();
    });

    it('preserves platform-specific line item extension properties', () => {
      const sakaiReadOnlyProperty = 'https://www.sakailms.org/spec/lti-ags/v2p0/readOnly';

      const parsed = LineItemSchema.parse({
        id: 'https://platform.example.com/ags/lineitems/123',
        scoreMaximum: 100,
        label: 'Midterm',
        [sakaiReadOnlyProperty]: true,
      });

      expect(parsed[sakaiReadOnlyProperty]).toBe(true);
    });

    it('preserves platform-specific result extension properties', () => {
      const platformExtensionProperty =
        'https://platform.example.com/spec/lti-ags/resultStatus';

      const parsed = ResultSchema.parse({
        id: 'result-1',
        scoreOf: 'https://platform.example.com/ags/lineitems/123',
        userId: 'learner-1',
        resultScore: 95,
        [platformExtensionProperty]: 'released',
      });

      expect(parsed[platformExtensionProperty]).toBe('released');
    });
  });

  describe('HandleLoginParamsSchema', () => {
    it('rejects invalid launch URLs', () => {
      const invalidParams = {
        iss: 'https://platform.example.com',
        login_hint: 'user123',
        target_link_uri: 'https://tool.example.com/content',
        client_id: 'client123',
        lti_deployment_id: 'deployment1',
        launchUrl: 'not-a-url',
      };

      expect(() => HandleLoginParamsSchema.parse(invalidParams)).toThrow();
    });
  });

  describe('DynamicRegistrationFormSchema', () => {
    it('accepts a single selected service from form-urlencoded submissions', () => {
      const parsed = DynamicRegistrationFormSchema.parse({
        services: 'deep_linking',
        sessionToken: 'session-token-123',
      });

      expect(parsed).toEqual({
        services: ['deep_linking'],
        sessionToken: 'session-token-123',
      });
    });

    it('accepts multiple selected services as an array', () => {
      const parsed = DynamicRegistrationFormSchema.parse({
        services: ['ags', 'deep_linking'],
        sessionToken: 'session-token-123',
      });

      expect(parsed).toEqual({
        services: ['ags', 'deep_linking'],
        sessionToken: 'session-token-123',
      });
    });
  });

  describe('VerifyLaunchParamsSchema', () => {
    it('validates verify launch parameters', () => {
      const validParams = {
        idToken:
          'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3BsYXRmb3JtLmV4YW1wbGUuY29tIn0.signature',
        state: 'eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6InRlc3Qtbm9uY2UifQ.signature',
      };

      expect(() => VerifyLaunchParamsSchema.parse(validParams)).not.toThrow();
    });

    it('rejects empty strings', () => {
      const invalidParams = {
        idToken: '',
        state: 'valid-state',
      };

      expect(() => VerifyLaunchParamsSchema.parse(invalidParams)).toThrow();
    });
  });

  describe('SessionIdSchema', () => {
    it('validates non-empty session ID', () => {
      const validSessionId = 'session-123';
      expect(() => SessionIdSchema.parse(validSessionId)).not.toThrow();
    });

    it('rejects empty session ID', () => {
      expect(() => SessionIdSchema.parse('')).toThrow();
    });
  });

  describe('LTI13JwtPayloadSchema', () => {
    it('validates complete LTI 1.3 JWT payload', () => {
      const validPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
        [LTI_CLAIM_ROLES]: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'],
        [LTI_CLAIM_CONTEXT]: {
          id: 'course123',
          label: 'CS101',
          title: 'Introduction to Computer Science',
        },
        [LTI_CLAIM_RESOURCE_LINK]: {
          id: 'assignment456',
          title: 'Lab 1',
        },
      };

      expect(() => LTI13JwtPayloadSchema.parse(validPayload)).not.toThrow();
    });

    it('rejects payload with invalid target_link_uri', () => {
      const invalidPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'not-a-url',
      };

      expect(() => LTI13JwtPayloadSchema.parse(invalidPayload)).toThrow();
    });

    it('rejects payload with invalid message type', () => {
      const invalidPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        [LTI_CLAIM_MESSAGE_TYPE]: 'InvalidMessageType',
        [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
      };

      expect(() => LTI13JwtPayloadSchema.parse(invalidPayload)).toThrow();
    });

    it('rejects payload with invalid version', () => {
      const invalidPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: '2.0.0',
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
      };

      expect(() => LTI13JwtPayloadSchema.parse(invalidPayload)).toThrow();
    });

    it('rejects payload missing required user fields', () => {
      const invalidPayload = {
        iss: 'https://platform.example.com',
        sub: 'user123',
        aud: 'client123',
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: 'test-nonce',
        // missing given_name, family_name, name, email
        [LTI_CLAIM_MESSAGE_TYPE]: LTI_MESSAGE_TYPE_RESOURCE_LINK_REQUEST,
        [LTI_CLAIM_VERSION]: LTI_VERSION_1P3P0,
        [LTI_CLAIM_DEPLOYMENT_ID]: 'deployment1',
        [LTI_CLAIM_TARGET_LINK_URI]: 'https://tool.example.com/content',
      };

      expect(() => LTI13JwtPayloadSchema.parse(invalidPayload)).toThrow();
    });
  });

  describe('ScoreSubmissionSchema', () => {
    it('validates score submission with all fields', () => {
      const validSubmission = {
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
        scoreGiven: 85,
        scoreMaximum: 100,
        userId: 'user123',
        comment: 'Great work!',
        timestamp: new Date().toISOString(),
      };

      expect(() => ScoreSubmissionSchema.parse(validSubmission)).not.toThrow();
    });

    it('rejects invalid activity progress', () => {
      const invalidSubmission = {
        activityProgress: 'InvalidProgress',
        gradingProgress: 'FullyGraded',
        userId: 'user123',
      };

      expect(() => ScoreSubmissionSchema.parse(invalidSubmission)).toThrow();
    });

    it('rejects invalid grading progress', () => {
      const invalidSubmission = {
        activityProgress: 'Completed',
        gradingProgress: 'InvalidGrading',
        userId: 'user123',
      };

      expect(() => ScoreSubmissionSchema.parse(invalidSubmission)).toThrow();
    });

    it('rejects negative scores', () => {
      const invalidSubmission = {
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
        scoreGiven: -10,
        userId: 'user123',
      };

      expect(() => ScoreSubmissionSchema.parse(invalidSubmission)).toThrow();
    });

    it('rejects invalid timestamp format', () => {
      const invalidSubmission = {
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
        userId: 'user123',
        timestamp: 'not-a-valid-timestamp',
      };

      expect(() => ScoreSubmissionSchema.parse(invalidSubmission)).toThrow();
    });
  });

  describe('LTI13LaunchSchema', () => {
    it('validates launch parameters', () => {
      const validLaunch = {
        id_token:
          'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL3BsYXRmb3JtLmV4YW1wbGUuY29tIn0.signature',
        state: 'eyJhbGciOiJIUzI1NiJ9.eyJub25jZSI6InRlc3Qtbm9uY2UifQ.signature',
      };

      expect(() => LTI13LaunchSchema.parse(validLaunch)).not.toThrow();
    });
  });

  describe('NRPSContextMembershipResponseSchema', () => {
    it('accepts Sakai-like context objects without label/title', () => {
      const payload = {
        id: 'https://platform.example.com/memberships/ctx-1',
        context: {
          id: 'ctx-1',
        },
        members: [
          {
            status: 'Active',
            name: 'Jane Doe',
            user_id: 'user-1',
            roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Instructor'],
          },
        ],
      };

      expect(() => NRPSContextMembershipResponseSchema.parse(payload)).not.toThrow();
    });
  });
});
