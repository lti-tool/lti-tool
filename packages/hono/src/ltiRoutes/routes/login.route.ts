import { LTI13LoginSchema, type LTIConfig } from '@lti-tool/core';
import { type Handler } from 'hono';
import { ZodError } from 'zod';

import { getLTITool } from '../../ltiTool';

/**
 * Creates a route handler for LTI login requests.
 * @param config - The LTI config
 * @returns Route handler for LTI login
 */
export function loginRouteHandler(config: LTIConfig): Handler {
  return async (c) => {
    try {
      let params;
      if (c.req.method === 'GET') {
        params = LTI13LoginSchema.parse({
          iss: c.req.query('iss'),
          login_hint: c.req.query('login_hint'),
          target_link_uri: c.req.query('target_link_uri'),
          client_id: c.req.query('client_id'),
          lti_deployment_id: c.req.query('lti_deployment_id'),
          lti_message_hint: c.req.query('lti_message_hint') || undefined,
        });
      } else {
        const formData = await c.req.formData();
        params = LTI13LoginSchema.parse({
          iss: formData.get('iss'),
          login_hint: formData.get('login_hint'),
          target_link_uri: formData.get('target_link_uri'),
          client_id: formData.get('client_id'),
          lti_deployment_id: formData.get('lti_deployment_id'),
          lti_message_hint: formData.get('lti_message_hint') || undefined,
        });
      }

      const ltiTool = getLTITool(config);
      const baseUrl = new URL(c.req.url).origin;
      const currentPath = new URL(c.req.url).pathname;
      const launchPath = currentPath.replace(/\/login$/, '/launch');
      const launchUrl = new URL(launchPath, baseUrl);

      const authRedirectUrl = await ltiTool.handleLogin({
        ...params,
        launchUrl,
      });

      return c.redirect(authRedirectUrl);
    } catch (error) {
      config.logger?.error({ error, path: c.req.path }, 'Login endpoint error');
      if (error instanceof ZodError) {
        return c.json({ error: 'Invalid request parameters' }, 400);
      }
      return c.json({ error: 'Internal server error' }, 500);
    }
  };
}
