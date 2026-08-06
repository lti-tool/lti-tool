import { SignJWT } from 'jose';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { LTI_AGS_SCOPE_SCORE } from '../src/constants.js';
import { TokenService } from '../src/services/token.service.js';

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

// Mock crypto.randomUUID for consistent UUIDs in tests
const originalRandomUUID = global.crypto.randomUUID;
beforeAll(() => {
  global.crypto.randomUUID = vi.fn(() => 'test-uuid-123') as any;
});

afterAll(() => {
  global.crypto.randomUUID = originalRandomUUID;
});

// Mock SignJWT from jose
vi.mock('jose', () => ({
  SignJWT: vi.fn(),
}));

const mockSignJWT = vi.mocked(SignJWT);

// Mock RSA key pair
const mockKeyPair: CryptoKeyPair = {
  privateKey: { type: 'private' } as CryptoKey,
  publicKey: { type: 'public' } as CryptoKey,
};

describe('TokenService', () => {
  let tokenService: TokenService;

  beforeEach(() => {
    vi.clearAllMocks();
    tokenService = new TokenService(mockKeyPair);
  });

  describe('createClientAssertion', () => {
    it('creates a valid JWT client assertion with default key ID', async () => {
      const mockSign = vi.fn().mockResolvedValue('mock.jwt.token');
      const mockSetProtectedHeader = vi.fn().mockReturnValue({ sign: mockSign });

      mockSignJWT.mockImplementation(function () {
        return {
          setProtectedHeader: mockSetProtectedHeader,
        } as any;
      });

      const clientId = 'test-client';
      const tokenUrl = 'https://platform.example.com/token';

      const result = await tokenService.createClientAssertion(clientId, tokenUrl);

      expect(result).toBe('mock.jwt.token');
      expect(mockSignJWT).toHaveBeenCalledWith({
        iss: clientId,
        sub: clientId,
        aud: tokenUrl,
        iat: expect.any(Number),
        exp: expect.any(Number),
        jti: 'test-uuid-123',
      });
      expect(mockSetProtectedHeader).toHaveBeenCalledWith({
        alg: 'RS256',
        kid: 'main', // default key ID
        typ: 'JWT',
      });
      expect(mockSign).toHaveBeenCalledWith(mockKeyPair.privateKey);
    });
  });

  describe('getBearerToken', () => {
    beforeEach(() => {
      // Mock createClientAssertion
      vi.spyOn(tokenService, 'createClientAssertion').mockResolvedValue('mock-assertion');
    });

    it('successfully obtains bearer token', async () => {
      const mockResponse = {
        ok: true,
        json: vi.fn().mockResolvedValue({
          access_token: 'bearer-token-123',
          token_type: 'Bearer',
          expires_in: 3600,
        }),
      };
      mockFetch.mockResolvedValue(mockResponse);

      const result = await tokenService.getBearerToken(
        'client123',
        'https://platform.example.com/token',
        LTI_AGS_SCOPE_SCORE,
      );

      expect(result).toBe('bearer-token-123');
      expect(mockFetch).toHaveBeenCalledWith(
        'https://platform.example.com/token',
        expect.objectContaining({
          method: 'POST',
          body: expect.any(URLSearchParams),
        }),
      );
      // Verify headers separately
      const [_url, options] = mockFetch.mock.calls[0];
      const headers = options.headers as Headers;
      expect(headers.get('Content-Type')).toBe('application/x-www-form-urlencoded');
      expect(headers.get('User-Agent')).toMatch(/^lti-tool\/\d+\.\d+\.\d+/);

      // Verify URLSearchParams content
      const fetchCall = mockFetch.mock.calls[0];
      const body = fetchCall[1].body as URLSearchParams;
      expect(body.get('grant_type')).toBe('client_credentials');
      expect(body.get('client_assertion_type')).toBe(
        'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      );
      expect(body.get('client_assertion')).toBe('mock-assertion');
      expect(body.get('scope')).toBe(LTI_AGS_SCOPE_SCORE);
    });

    it('throws error when HTTP request fails', async () => {
      const mockResponse = {
        ok: false,
        status: 400,
        statusText: 'Bad Request',
        json: vi.fn().mockResolvedValue('Error details'),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(
        tokenService.getBearerToken(
          'client123',
          'https://platform.example.com/token',
          'scope',
        ),
      ).rejects.toThrow('Token request failed: 400 Bad Request');
    });

    it('throws error when response has no access_token', async () => {
      const mockResponse = {
        ok: true,
        json: vi.fn().mockResolvedValue({
          error: 'invalid_client',
          error_description: 'Client authentication failed',
        }),
      };
      mockFetch.mockResolvedValue(mockResponse);

      await expect(
        tokenService.getBearerToken(
          'client123',
          'https://platform.example.com/token',
          'scope',
        ),
      ).rejects.toThrow('Token response missing access_token');
    });
  });
});
