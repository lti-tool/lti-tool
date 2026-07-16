import type { BaseLogger } from 'pino';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  LTI_AGS_SCOPE_LINEITEM_READONLY,
  LTI_AGS_SCOPE_RESULT_READONLY,
  LTI_AGS_SCOPE_SCORE,
} from '../src/constants.js';
import type { LTISession, LTIStorage } from '../src/interfaces/index.js';
import type { ScoreSubmission } from '../src/schemas/lti13/ags/scoreSubmission.schema.js';
import { AGSService } from '../src/services/ags.service.js';
import { TokenService } from '../src/services/token.service.js';
import { getValidLaunchConfig } from '../src/utils/launchConfigValidation.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock TokenService
vi.mock('../src/services/token.service.js', () => ({
  TokenService: vi.fn().mockImplementation(() => ({
    getBearerToken: vi.fn(),
  })),
}));

// Mock getValidLaunchConfig utility
vi.mock('../src/utils/launchConfigValidation.js', () => ({
  getValidLaunchConfig: vi.fn(),
}));

const mockGetValidLaunchConfig = vi.mocked(getValidLaunchConfig);
const MockedTokenService = vi.mocked(TokenService);

const mockLogger: BaseLogger = {
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
  fatal: vi.fn(),
  trace: vi.fn(),
  silent: vi.fn(),
  level: 'info',
  msgPrefix: '',
};

const mockStorage: LTIStorage = {
  // Add minimal mock methods - we only need the interface to exist
  listClients: vi.fn(),
  getClientById: vi.fn(),
  addClient: vi.fn(),
  updateClient: vi.fn(),
  deleteClient: vi.fn(),
  listDeployments: vi.fn(),
  getDeployment: vi.fn(),
  addDeployment: vi.fn(),
  updateDeployment: vi.fn(),
  deleteDeployment: vi.fn(),
  getSession: vi.fn(),
  addSession: vi.fn(),
  storeNonce: vi.fn(),
  validateNonce: vi.fn(),
  getLaunchConfig: vi.fn(),
  saveLaunchConfig: vi.fn(),
  setRegistrationSession: vi.fn(),
  getRegistrationSession: vi.fn(),
  deleteRegistrationSession: vi.fn(),
};

const mockSession: LTISession = {
  id: 'session123',
  jwtPayload: {},
  user: { id: 'user123', roles: ['student'] },
  context: { id: 'context123', label: 'TEST', title: 'Test Course' },
  platform: {
    issuer: 'https://platform.example.com',
    clientId: 'client123',
    deploymentId: 'deployment1',
    name: 'Test Platform',
  },
  launch: { target: 'https://tool.example.com/launch' },
  customParameters: {},
  isAdmin: false,
  isInstructor: false,
  isStudent: true,
  isAssignmentAndGradesAvailable: true,
  isDeepLinkingAvailable: false,
  isNameAndRolesAvailable: false,
  services: {
    ags: {
      lineitem: 'https://platform.example.com/api/ags/lineitem/123',
      lineitems: 'https://platform.example.com/api/ags/lineitems',
      scopes: [LTI_AGS_SCOPE_SCORE],
    },
  },
};

const mockLaunchConfig = {
  iss: 'https://platform.example.com',
  clientId: 'client123',
  deploymentId: 'deployment1',
  authUrl: 'https://platform.example.com/auth',
  tokenUrl: 'https://platform.example.com/token',
  jwksUrl: 'https://platform.example.com/.well-known/jwks',
};

const mockScoreSubmission: ScoreSubmission = {
  userId: 'user123',
  scoreGiven: 85,
  scoreMaximum: 100,
  comment: 'Good work!',
  activityProgress: 'Completed',
  gradingProgress: 'FullyGraded',
};

describe('AGSService', () => {
  let agsService: AGSService;
  let mockTokenService: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Create mock token service instance
    mockTokenService = {
      getBearerToken: vi.fn(),
    };
    MockedTokenService.mockImplementation(() => mockTokenService);

    agsService = new AGSService(mockTokenService, mockStorage, mockLogger);
  });

  describe('submitScore', () => {
    beforeEach(() => {
      mockGetValidLaunchConfig.mockResolvedValue(mockLaunchConfig);
      mockTokenService.getBearerToken.mockResolvedValue('mock-bearer-token');
    });

    it('successfully submits score to platform', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await agsService.submitScore(mockSession, mockScoreSubmission);

      expect(result).toBe(mockResponse);

      // Verify token service was called correctly
      expect(mockTokenService.getBearerToken).toHaveBeenCalledWith(
        'client123',
        'https://platform.example.com/token',
        LTI_AGS_SCOPE_SCORE,
      );

      // Verify fetch was called correctly
      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitem/123/scores',
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"userId":"user123"'),
        }),
      );
      // Verify headers separately
      const [_url, options] = mockFetch.mock.calls[0];
      const headers = options.headers as Headers;
      expect(headers.get('Authorization')).toBe('Bearer mock-bearer-token');
      expect(headers.get('Content-Type')).toBe('application/vnd.ims.lis.v1.score+json');
      expect(headers.get('User-Agent')).toMatch(/^lti-tool\/\d+\.\d+\.\d+/);

      // Verify score payload structure
      const fetchCall = mockFetch.mock.calls[0];
      const payload = JSON.parse(fetchCall[1].body);
      expect(payload).toEqual({
        userId: 'user123',
        scoreGiven: 85,
        scoreMaximum: 100,
        comment: 'Good work!',
        timestamp: expect.any(String),
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
      });
    });

    it('throws error when AGS not available', async () => {
      const sessionWithoutAGS = {
        ...mockSession,
        services: undefined,
      };

      await expect(
        agsService.submitScore(sessionWithoutAGS, mockScoreSubmission),
      ).rejects.toThrow('AGS not available for this session');

      expect(mockTokenService.getBearerToken).not.toHaveBeenCalled();
      expect(mockFetch).not.toHaveBeenCalled();
    });

    it('throws error when platform returns error response', async () => {
      const mockErrorResponse = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: vi.fn().mockResolvedValue({
          error: 'invalid_score',
          error_description: 'Score value is invalid',
        }),
      };
      mockFetch.mockResolvedValue(mockErrorResponse);

      await expect(
        agsService.submitScore(mockSession, mockScoreSubmission),
      ).rejects.toThrow('AGS score submission failed: Bad Request');

      // Verify error was logged
      expect(mockLogger.error).toHaveBeenCalledWith(
        {
          error: { error: 'invalid_score', error_description: 'Score value is invalid' },
          status: 400,
          statusText: 'Bad Request',
        },
        'AGS score submission failed',
      );
    });
  });

  describe('getScores', () => {
    beforeEach(() => {
      mockGetValidLaunchConfig.mockResolvedValue(mockLaunchConfig);
      mockTokenService.getBearerToken.mockResolvedValue('mock-bearer-token');
    });

    it('retrieves results from the session line item by default', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await agsService.getScores(mockSession);

      expect(result).toBe(mockResponse);
      expect(mockTokenService.getBearerToken).toHaveBeenCalledWith(
        'client123',
        'https://platform.example.com/token',
        LTI_AGS_SCOPE_RESULT_READONLY,
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitem/123/results',
        expect.objectContaining({
          method: 'GET',
        }),
      );
    });

    it('retrieves results from a caller-provided line item URL', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      await agsService.getScores(mockSession, {
        lineItemUrl: 'https://platform.example.com/api/ags/lineitems/456',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitems/456/results',
        expect.objectContaining({
          method: 'GET',
        }),
      );
    });

    it('retrieves filtered results while preserving line item URL query parameters', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      await agsService.getScores(mockSession, {
        lineItemUrl: 'https://platform.example.com/api/ags/lineitems/456?existing=1',
        userId: 'learner-1',
        limit: 25,
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitems/456/results?existing=1&user_id=learner-1&limit=25',
        expect.objectContaining({
          method: 'GET',
        }),
      );
    });
  });

  describe('listLineItems', () => {
    beforeEach(() => {
      mockGetValidLaunchConfig.mockResolvedValue(mockLaunchConfig);
      mockTokenService.getBearerToken.mockResolvedValue('mock-bearer-token');
    });

    it('lists line items with optional AGS filters', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      await agsService.listLineItems(mockSession, {
        resourceId: 'resource-1',
        resourceLinkId: 'resource-link-1',
        tag: 'badges',
        limit: 50,
      });

      expect(mockTokenService.getBearerToken).toHaveBeenCalledWith(
        'client123',
        'https://platform.example.com/token',
        LTI_AGS_SCOPE_LINEITEM_READONLY,
      );
      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitems?resource_id=resource-1&resource_link_id=resource-link-1&tag=badges&limit=50',
        expect.objectContaining({
          method: 'GET',
        }),
      );
    });
  });

  describe('getLineItem', () => {
    beforeEach(() => {
      mockGetValidLaunchConfig.mockResolvedValue(mockLaunchConfig);
      mockTokenService.getBearerToken.mockResolvedValue('mock-bearer-token');
    });

    it('retrieves a caller-provided line item URL', async () => {
      const mockResponse = {
        ok: true,
        status: 200,
        statusText: 'OK',
      };
      mockFetch.mockResolvedValue(mockResponse);

      await agsService.getLineItem(mockSession, {
        lineItemUrl: 'https://platform.example.com/api/ags/lineitems/456',
      });

      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/api/ags/lineitems/456',
        expect.objectContaining({
          method: 'GET',
        }),
      );
    });
  });
});
