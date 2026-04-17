import {
  DynamicRegistrationFormSchema,
  RegistrationRequestSchema,
  type LTIConfig,
} from '@lti-tool/core';
import { type Handler } from 'hono';

import { getLTITool } from '../../ltiTool';

/**
 * Creates a Hono route handler for initiating LTI 1.3 dynamic registration.
 * Fetches platform configuration, creates a registration session, and renders a service selection form.
 *
 * @param config - LTI tool configuration containing dynamic registration settings
 * @returns Hono handler that processes registration initiation requests and returns HTML form
 */
export function initiateDynamicRegistrationRouteHandler(config: LTIConfig): Handler {
  return async (c) => {
    const queryData = c.req.query();
    const validated = RegistrationRequestSchema.parse(queryData);
    const ltiTool = getLTITool(config);
    const formHtml = await ltiTool.initiateDynamicRegistration(validated, c.req.path);

    return c.html(formHtml);
  };
}

/**
 * Creates a Hono route handler for completing LTI 1.3 dynamic registration.
 * Processes form submission, registers with platform, stores client configuration, and returns success page.
 *
 * @param config - LTI tool configuration containing dynamic registration settings
 * @returns Hono handler that processes registration completion and returns HTML success page
 */
export function completeDynamicRegistrationRouteHandler(config: LTIConfig): Handler {
  return async (c) => {
    try {
      // 1. Parse and validate form data
      const formData = await c.req.parseBody({ all: true }); // services array parsing requires all param
      const normalizedFormData = {
        ...formData,
        services:
          typeof formData.services === 'string' ? [formData.services] : formData.services,
      };
      const validated = DynamicRegistrationFormSchema.parse(normalizedFormData);

      const ltiTool = getLTITool(config);
      const successHtml = await ltiTool.completeDynamicRegistration(validated);

      return c.html(successHtml);
    } catch (error) {
      config.logger?.error({ error }, 'lti dynamic registration completion error');
      return c.json({ error: 'Invalid request data' }, 400);
    }
  };
}
