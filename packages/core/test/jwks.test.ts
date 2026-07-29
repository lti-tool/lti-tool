import { decodeProtectedHeader, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import type { BaseLogger, Logger } from 'pino';
import { beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import type { LTIConfig, LTISession, LTIStorage } from '../src/interfaces/index.js';
import { LTITool } from '../src/ltiTool.js';

const mockFetch = vi.fn();
global.fetch = mockFetch;

const createMockStorage = (): LTIStorage =>
  ({
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
    getLaunchConfig: vi.fn().mockResolvedValue({
      iss: 'https://platform.example.com',
      clientId: 'client123',
      deploymentId: 'deployment1',
      authUrl: 'https://platform.example.com/auth',
      tokenUrl: 'https://platform.example.com/token',
      jwksUrl: 'https://platform.example.com/jwks',
    }),
    saveLaunchConfig: vi.fn(),
    setRegistrationSession: vi.fn(),
    getRegistrationSession: vi.fn(),
    deleteRegistrationSession: vi.fn(),
  }) as unknown as LTIStorage;

const createMockLogger = (): BaseLogger =>
  ({
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    fatal: vi.fn(),
    trace: vi.fn(),
    silent: vi.fn(),
    level: 'info',
    msgPrefix: '',
  }) as BaseLogger;

const createSession = (): LTISession => ({
  id: 'session123',
  jwtPayload: {},
  user: { id: 'user123', roles: ['instructor'] },
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
  isInstructor: true,
  isStudent: false,
  isAssignmentAndGradesAvailable: true,
  isDeepLinkingAvailable: true,
  isNameAndRolesAvailable: false,
  services: {
    ags: {
      lineitem: 'https://platform.example.com/api/ags/lineitem/123',
      lineitems: 'https://platform.example.com/api/ags/lineitems',
      scopes: ['https://purl.imsglobal.org/spec/lti-ags/scope/score'],
    },
    deepLinking: {
      returnUrl: 'https://platform.example.com/deep-linking/return',
      acceptTypes: ['ltiResourceLink'],
      acceptPresentationDocumentTargets: ['iframe'],
      acceptMultiple: false,
      autoCreate: false,
      data: 'opaque-platform-data',
    },
  },
});

describe('JWKS publishing', () => {
  let keyPair: CryptoKeyPair;
  let retiredKeyPair: CryptoKeyPair;
  let otherKeyPair: CryptoKeyPair;
  let logger: BaseLogger;

  beforeAll(async () => {
    keyPair = await generateKeyPair('RS256', { extractable: true });
    retiredKeyPair = await generateKeyPair('RS256', { extractable: true });
    otherKeyPair = await generateKeyPair('RS256', { extractable: true });
  });

  beforeEach(() => {
    vi.clearAllMocks();
    logger = createMockLogger();
  });

  const createTool = (overrides: Partial<LTIConfig> = {}): LTITool =>
    new LTITool({
      stateSecret: new TextEncoder().encode('test-secret-key-32-bytes-long!!!'),
      keyPair,
      storage: createMockStorage(),
      logger: logger as unknown as Logger,
      ...overrides,
    });

  describe('active signing key', () => {
    it('publishes exactly one key when no additional keys are configured', async () => {
      const jwks = await createTool({ security: { keyId: 'test-key' } }).getJWKS();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].use).toBe('sig');
      expect(jwks.keys[0].alg).toBe('RS256');
      expect(jwks.keys[0].kid).toBe('test-key');
      expect(jwks.keys[0].kty).toBe('RSA');
    });

    it('defaults the active key ID to main', async () => {
      const jwks = await createTool().getJWKS();

      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys[0].kid).toBe('main');
    });

    it('produces output identical to the single-key baseline', async () => {
      const jwks = await createTool({ security: { keyId: 'test-key' } }).getJWKS();

      const baseline = {
        keys: [
          {
            ...(await exportJWK(keyPair.publicKey)),
            use: 'sig',
            alg: 'RS256',
            kid: 'test-key',
          },
        ],
      };

      expect(JSON.stringify(jwks)).toBe(JSON.stringify(baseline));
    });
  });

  describe('additional public keys', () => {
    it('publishes additional keys alongside the active key', async () => {
      const jwks = await createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
        security: { keyId: '2026-02' },
      }).getJWKS();

      expect(jwks.keys).toHaveLength(2);
      expect(jwks.keys.map((key) => key.kid)).toEqual(['2026-02', '2026-01']);
      expect(jwks.keys.every((key) => key.use === 'sig')).toBe(true);
      expect(jwks.keys.every((key) => typeof key.alg === 'string')).toBe(true);
      expect(jwks.keys[1].n).toBe((await exportJWK(retiredKeyPair.publicKey)).n);
    });

    it('defaults an additional key alg to RS256', async () => {
      const jwks = await createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
        security: { keyId: '2026-02' },
      }).getJWKS();

      expect(jwks.keys[1].alg).toBe('RS256');
    });

    it('honors an additional key alg when provided', async () => {
      const jwks = await createTool({
        additionalPublicKeys: [
          { publicKey: retiredKeyPair.publicKey, kid: '2026-01', alg: 'RS384' },
        ],
        security: { keyId: '2026-02' },
      }).getJWKS();

      expect(jwks.keys[1].alg).toBe('RS384');
      expect(jwks.keys[0].alg).toBe('RS256');
    });
  });

  describe('signing is unaffected by additional keys', () => {
    it('signs deep linking responses with the active key', async () => {
      const ltiTool = createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
        security: { keyId: '2026-02' },
      });

      const html = await ltiTool.createDeepLinkingResponse(createSession(), [
        {
          type: 'ltiResourceLink',
          title: 'Quiz 1',
          url: 'https://tool.example.com/quiz/1',
        },
      ]);

      const jwt = html.match(/name="JWT" value="([^"]+)"/)?.[1];
      expect(jwt).toBeDefined();

      expect(decodeProtectedHeader(jwt!).kid).toBe('2026-02');
      await expect(jwtVerify(jwt!, keyPair.publicKey)).resolves.toBeDefined();
      await expect(jwtVerify(jwt!, retiredKeyPair.publicKey)).rejects.toThrow();
    });

    it('signs client assertions with the active key', async () => {
      const ltiTool = createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
        security: { keyId: '2026-02' },
      });

      mockFetch
        .mockResolvedValueOnce({
          ok: true,
          json: vi.fn().mockResolvedValue({ access_token: 'bearer-token' }),
        })
        .mockResolvedValueOnce({
          ok: true,
          status: 200,
          json: vi.fn().mockResolvedValue({}),
        });

      await ltiTool.submitScore(createSession(), {
        userId: 'user123',
        scoreGiven: 85,
        scoreMaximum: 100,
        activityProgress: 'Completed',
        gradingProgress: 'FullyGraded',
      });

      const tokenRequestBody = mockFetch.mock.calls[0][1].body as URLSearchParams;
      const assertion = tokenRequestBody.get('client_assertion')!;

      expect(decodeProtectedHeader(assertion).kid).toBe('2026-02');
      await expect(jwtVerify(assertion, keyPair.publicKey)).resolves.toBeDefined();
    });
  });

  describe('duplicate key IDs', () => {
    it('throws when an additional key collides with the default active kid', () => {
      expect(() =>
        createTool({
          additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: 'main' }],
        }),
      ).toThrow(/main/);
    });

    it('throws when an additional key collides with a configured active kid', () => {
      expect(() =>
        createTool({
          additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-02' }],
          security: { keyId: '2026-02' },
        }),
      ).toThrow(/2026-02/);
    });

    it('throws when two additional keys share a kid', () => {
      expect(() =>
        createTool({
          additionalPublicKeys: [
            { publicKey: retiredKeyPair.publicKey, kid: '2026-01' },
            { publicKey: otherKeyPair.publicKey, kid: '2026-01' },
          ],
          security: { keyId: '2026-02' },
        }),
      ).toThrow(/2026-01/);
    });

    it('accepts distinct key IDs', () => {
      expect(() =>
        createTool({
          additionalPublicKeys: [
            { publicKey: retiredKeyPair.publicKey, kid: '2026-01' },
            { publicKey: otherKeyPair.publicKey, kid: '2025-12' },
          ],
          security: { keyId: '2026-02' },
        }),
      ).not.toThrow();
    });
  });

  describe('default key ID warning', () => {
    it('warns when additional keys are configured with the default active kid', () => {
      createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
      });

      expect(logger.warn).toHaveBeenCalledWith(expect.stringContaining('security.keyId'));
    });

    it('does not warn without additional keys', () => {
      createTool();

      expect(logger.warn).not.toHaveBeenCalled();
    });

    it('does not warn when the active key ID is set', () => {
      createTool({
        additionalPublicKeys: [{ publicKey: retiredKeyPair.publicKey, kid: '2026-01' }],
        security: { keyId: '2026-02' },
      });

      expect(logger.warn).not.toHaveBeenCalled();
    });
  });
});
