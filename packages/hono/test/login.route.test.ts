import type { LTIConfig } from '@lti-tool/core';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { loginRouteHandler } from '../src/ltiRoutes/routes/login.route';

const handleLoginMock = vi.fn();

vi.mock('../src/ltiTool', () => ({
  getLTITool: () => ({
    handleLogin: handleLoginMock,
  }),
}));

describe('loginRouteHandler', () => {
  const config = {} as LTIConfig;

  beforeEach(() => {
    handleLoginMock.mockReset();
  });

  it('accepts OIDC login-init params from GET query string', async () => {
    handleLoginMock.mockResolvedValueOnce('https://platform.example/authorize');

    const app = new Hono();
    app.get('/lti/login', loginRouteHandler(config));

    const response = await app.request(
      '/lti/login?iss=https%3A%2F%2Fsakai.example&login_hint=abc123&target_link_uri=https%3A%2F%2Ftool.example%2Flti%2Flaunch&client_id=client-1&lti_deployment_id=dep-1',
      { method: 'GET' },
    );

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://platform.example/authorize');
    expect(handleLoginMock).toHaveBeenCalledOnce();
  });

  it('accepts OIDC login-init params from POST form body', async () => {
    handleLoginMock.mockResolvedValueOnce('https://platform.example/authorize');

    const app = new Hono();
    app.post('/lti/login', loginRouteHandler(config));

    const body = new URLSearchParams({
      iss: 'https://sakai.example',
      login_hint: 'abc123',
      target_link_uri: 'https://tool.example/lti/launch',
      client_id: 'client-1',
      lti_deployment_id: 'dep-1',
    });

    const response = await app.request('/lti/login', {
      method: 'POST',
      body: body.toString(),
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
    });

    expect(response.status).toBe(302);
    expect(response.headers.get('location')).toBe('https://platform.example/authorize');
    expect(handleLoginMock).toHaveBeenCalledOnce();
  });

  it('returns 400 when required params are missing', async () => {
    const app = new Hono();
    app.get('/lti/login', loginRouteHandler(config));

    const response = await app.request('/lti/login?iss=https%3A%2F%2Fsakai.example', {
      method: 'GET',
    });

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      error: 'Invalid request parameters',
    });
  });
});
