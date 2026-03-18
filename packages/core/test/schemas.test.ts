import { describe, expect, it } from 'vitest';

import {
  HandleLoginParamsSchema,
  LTI13JwtPayloadSchema,
  LTI13LaunchSchema,
  LTI13LoginSchema,
  SessionIdSchema,
  VerifyLaunchParamsSchema,
} from '../src/schemas/index.js';
import { ScoreSubmissionSchema } from '../src/schemas/lti13/ags/scoreSubmission.schema.js';
import { NRPSContextMembershipResponseSchema } from '../src/schemas/lti13/nrps/contextMembership.schema.js';

describe('Schema Validation Tests', () => {
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
        'https://purl.imsglobal.org/spec/lti/claim/message_type':
          'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri':
          'https://tool.example.com/content',
        'https://purl.imsglobal.org/spec/lti/claim/roles': [
          'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
        ],
        'https://purl.imsglobal.org/spec/lti/claim/context': {
          id: 'course123',
          label: 'CS101',
          title: 'Introduction to Computer Science',
        },
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
          id: 'assignment456',
          title: 'Lab 1',
        },
      };

      expect(() => LTI13JwtPayloadSchema.parse(validPayload)).not.toThrow();
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
        'https://purl.imsglobal.org/spec/lti/claim/message_type': 'InvalidMessageType',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri':
          'https://tool.example.com/content',
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
        'https://purl.imsglobal.org/spec/lti/claim/message_type':
          'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '2.0.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri':
          'https://tool.example.com/content',
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
        'https://purl.imsglobal.org/spec/lti/claim/message_type':
          'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri':
          'https://tool.example.com/content',
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
