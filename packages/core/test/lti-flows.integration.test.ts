import { createRemoteJWKSet, generateKeyPair, jwtVerify } from 'jose';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { LTIConfig, LTIStorage } from '../src/interfaces/index.js';
import { LTITool } from '../src/ltiTool.js';

import { createMockLTIPayload } from './helpers/fixtures.js';

// Mock createRemoteJWKSet from jose to avoid actual HTTP calls
vi.mock('jose', async () => {
  const actual = await vi.importActual('jose');
  return {
    ...actual,
    createRemoteJWKSet: vi.fn(),
    jwtVerify: vi.fn(actual.jwtVerify),
  };
});

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Create a mock storage implementation
const createMockStorage = (): LTIStorage => ({
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
  addSession: vi.fn().mockResolvedValue('session-id'),
  storeNonce: vi.fn(),
  validateNonce: vi.fn(),
  getLaunchConfig: vi.fn(),
  saveLaunchConfig: vi.fn(),
  deleteRegistrationSession: vi.fn(),
  getRegistrationSession: vi.fn(),
  setRegistrationSession: vi.fn(),
});

describe('LTI Integration Tests', () => {
  let ltiTool: LTITool;
  let mockStorage: LTIStorage;
  let keyPair: CryptoKeyPair;
  let platformKeyPair: CryptoKeyPair;
  let stateSecret: Uint8Array;

  beforeAll(async () => {
    // Generate real key pairs for JWT signing/verification
    keyPair = await generateKeyPair('RS256');
    platformKeyPair = await generateKeyPair('RS256');
  });

  beforeEach(() => {
    vi.clearAllMocks();

    stateSecret = new TextEncoder().encode('test-state-secret-exactly32bytes');

    mockStorage = createMockStorage();

    const config: LTIConfig = {
      keyPair,
      stateSecret,
      storage: mockStorage,
      security: {
        keyId: 'test-key',
        stateExpirationSeconds: 300,
        nonceExpirationSeconds: 300,
      },
    };

    ltiTool = new LTITool(config);

    // Setup default storage mocks
    vi.mocked(mockStorage.getLaunchConfig).mockResolvedValue({
      iss: 'https://platform.example.com',
      clientId: 'client123',
      deploymentId: 'deployment1',
      authUrl: 'https://platform.example.com/auth',
      tokenUrl: 'https://platform.example.com/token',
      jwksUrl: 'https://platform.example.com/.well-known/jwks',
    });

    vi.mocked(mockStorage.validateNonce).mockResolvedValue(true);

    // Mock createRemoteJWKSet to return a JWKS-compatible function
    const mockCreateRemoteJWKSet = vi.mocked(createRemoteJWKSet);
    mockCreateRemoteJWKSet.mockReturnValue((() => platformKeyPair.publicKey) as any);
  });

  describe('Login Flow', () => {
    it('generates valid login URL with state and nonce', async () => {
      const loginParams = {
        client_id: 'client123',
        iss: 'https://platform.example.com',
        launchUrl: 'https://tool.example.com/launch',
        login_hint: 'user123',
        target_link_uri: 'https://tool.example.com/content',
        lti_deployment_id: 'deployment1',
        lti_message_hint: 'hint123',
      };

      const authUrl = await ltiTool.handleLogin(loginParams);

      expect(authUrl).toMatch(/^https:\/\/platform\.example\.com\/auth\?/);

      const url = new URL(authUrl);
      expect(url.searchParams.get('scope')).toBe('openid');
      expect(url.searchParams.get('response_type')).toBe('id_token');
      expect(url.searchParams.get('response_mode')).toBe('form_post');
      expect(url.searchParams.get('client_id')).toBe('client123');
      expect(url.searchParams.get('redirect_uri')).toBe(
        'https://tool.example.com/launch',
      );
      expect(url.searchParams.get('login_hint')).toBe('user123');
      expect(url.searchParams.get('lti_deployment_id')).toBe('deployment1');
      expect(url.searchParams.get('lti_message_hint')).toBe('hint123');
      expect(url.searchParams.get('state')).toBeTruthy();
      expect(url.searchParams.get('nonce')).toBeTruthy();

      // Verify nonce was stored
      expect(mockStorage.storeNonce).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(Date),
      );
    });

    it('throws error when launch config not found', async () => {
      vi.mocked(mockStorage.getLaunchConfig).mockResolvedValue(undefined);

      const loginParams = {
        client_id: 'unknown-client',
        iss: 'https://unknown.platform.com',
        launchUrl: 'https://tool.example.com/launch',
        login_hint: 'user123',
        target_link_uri: 'https://tool.example.com/content',
        lti_deployment_id: 'deployment1',
      };

      await expect(ltiTool.handleLogin(loginParams)).rejects.toThrow(
        'No valid launch config found',
      );
    });
  });

  describe('Session Creation Flow', () => {
    it('creates session from validated JWT payload', async () => {
      const ltiPayload = createMockLTIPayload();

      const session = await ltiTool.createSession(ltiPayload as any);

      expect(session.user.name).toBe('Jane Smith');
      expect(session.user.email).toBe('jane.smith@university.edu');
      expect(session.isInstructor).toBe(true);
      expect(session.isStudent).toBe(false);
      expect(session.context.label).toBe('MATH201');
      expect(session.context.title).toBe('Advanced Mathematics');
      expect(session.resourceLink?.title).toBe('Homework 3');
      expect(session.isAssignmentAndGradesAvailable).toBe(true);
      expect(session.services?.ags?.lineitem).toBe(
        'https://platform.example.com/api/ags/lineitem/789',
      );

      // Verify session was stored
      expect(mockStorage.addSession).toHaveBeenCalledWith(session);
    });
  });

  describe('JWKS Generation', () => {
    it('generates valid JWKS with configured key ID', async () => {
      const jwks = await ltiTool.getJWKS();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].use).toBe('sig');
      expect(jwks.keys[0].alg).toBe('RS256');
      expect(jwks.keys[0].kid).toBe('test-key');
      expect(jwks.keys[0].kty).toBe('RSA');
    });
  });

  describe('JWT Verification', () => {
    it('refreshes JWKS and retries once on ERR_JWKS_NO_MATCHING_KEY', async () => {
      const ltiPayload = createMockLTIPayload({
        nonce: 'test-nonce',
      });
      const idTokenPayload = {
        iss: 'https://platform.example.com',
        aud: 'client123',
        nonce: 'test-nonce',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
      };
      const idToken = [
        Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'rotated-kid' })).toString(
          'base64url',
        ),
        Buffer.from(JSON.stringify(idTokenPayload)).toString('base64url'),
        'signature',
      ].join('.');

      const staleJwks = vi.fn();
      const freshJwks = vi.fn();
      vi.mocked(createRemoteJWKSet)
        .mockReturnValueOnce(staleJwks as any)
        .mockReturnValueOnce(freshJwks as any);

      const kidMissError = Object.assign(new Error('No matching key in JWKS'), {
        code: 'ERR_JWKS_NO_MATCHING_KEY',
      });
      vi.mocked(jwtVerify)
        .mockRejectedValueOnce(kidMissError as any)
        .mockResolvedValueOnce({ payload: ltiPayload } as any)
        .mockResolvedValueOnce({ payload: { nonce: 'test-nonce' } } as any);

      const validated = await ltiTool.verifyLaunch(idToken, 'state-token');

      expect(validated).toEqual(ltiPayload);
      expect(createRemoteJWKSet).toHaveBeenCalledTimes(2);
      expect(jwtVerify).toHaveBeenCalledTimes(3);
      expect(mockStorage.validateNonce).toHaveBeenCalledWith('test-nonce');
    });

    it('successfully verifies valid LTI launch JWT', async () => {
      // Create a valid LTI JWT using the platform key
      const ltiPayload = createMockLTIPayload({
        given_name: 'John',
        family_name: 'Doe',
        name: 'John Doe',
        email: 'john.doe@university.edu',
        'https://purl.imsglobal.org/spec/lti/claim/roles': [
          'http://purl.imsglobal.org/vocab/lis/v2/membership#Learner',
        ],
        'https://purl.imsglobal.org/spec/lti/claim/context': {
          id: 'course123',
          label: 'CS101',
        },
        'https://purl.imsglobal.org/spec/lti/claim/resource_link': {
          id: 'assignment789',
          title: 'Lab 1',
        },
      });

      // Sign the JWT with the platform's private key
      const { SignJWT } = await import('jose');
      const jwt = await new SignJWT(ltiPayload)
        .setProtectedHeader({ alg: 'RS256', kid: 'platform-key' })
        .sign(platformKeyPair.privateKey);

      // Create a state JWT (simulating what handleLogin would create)
      const statePayload = {
        nonce: 'test-nonce',
        iss: 'https://platform.example.com',
        client_id: 'client123',
        target_link_uri: 'https://tool.example.com/content',
        exp: Math.floor(Date.now() / 1000) + 300,
      };

      const stateJwt = await new SignJWT(statePayload)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(stateSecret);

      // Verify the launch JWT
      const validatedPayload = await ltiTool.verifyLaunch(jwt, stateJwt);

      // Create session from validated payload
      const session = await ltiTool.createSession(validatedPayload);

      expect(session.user.name).toBe('John Doe');
      expect(session.user.email).toBe('john.doe@university.edu');
      expect(session.isStudent).toBe(true);
      expect(session.isInstructor).toBe(false);
      expect(session.context.label).toBe('CS101');
      expect(session.resourceLink?.title).toBe('Lab 1');
    });

    it('rejects JWT with invalid signature', async () => {
      // Create a JWT signed with the wrong key
      const ltiPayload = {
        iss: 'https://platform.example.com',
        aud: 'client123',
        sub: 'user123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce: 'test-nonce',
        'https://purl.imsglobal.org/spec/lti/claim/message_type':
          'LtiResourceLinkRequest',
        'https://purl.imsglobal.org/spec/lti/claim/version': '1.3.0',
        'https://purl.imsglobal.org/spec/lti/claim/deployment_id': 'deployment1',
        'https://purl.imsglobal.org/spec/lti/claim/target_link_uri':
          'https://tool.example.com/content',
      };

      // Sign with the tool's key instead of platform key (wrong key)
      const { SignJWT } = await import('jose');
      const invalidJwt = await new SignJWT(ltiPayload)
        .setProtectedHeader({ alg: 'RS256', kid: 'wrong-key' })
        .sign(keyPair.privateKey);

      const statePayload = {
        nonce: 'test-nonce',
        iss: 'https://platform.example.com',
        client_id: 'client123',
        target_link_uri: 'https://tool.example.com/content',
        exp: Math.floor(Date.now() / 1000) + 300,
      };

      const stateJwt = await new SignJWT(statePayload)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(stateSecret);

      await expect(ltiTool.verifyLaunch(invalidJwt, stateJwt)).rejects.toThrow();
    });

    it('rejects JWT with invalid nonce', async () => {
      // Mock nonce validation to return false
      vi.mocked(mockStorage.validateNonce).mockResolvedValue(false);

      const ltiPayload = {
        iss: 'https://platform.example.com',
        aud: 'client123',
        sub: 'user123',
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + 300,
        nonce: 'invalid-nonce',
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
      };

      const { SignJWT } = await import('jose');
      const jwt = await new SignJWT(ltiPayload)
        .setProtectedHeader({ alg: 'RS256', kid: 'platform-key' })
        .sign(platformKeyPair.privateKey);

      const statePayload = {
        nonce: 'invalid-nonce',
        iss: 'https://platform.example.com',
        client_id: 'client123',
        target_link_uri: 'https://tool.example.com/content',
        exp: Math.floor(Date.now() / 1000) + 300,
      };

      const stateJwt = await new SignJWT(statePayload)
        .setProtectedHeader({ alg: 'HS256' })
        .sign(stateSecret);

      await expect(ltiTool.verifyLaunch(jwt, stateJwt)).rejects.toThrow(
        'Nonce has already been used or expired',
      );
    });
  });
});
