import * as z from 'zod';

/**
 * Zod schema for validating LTI 1.3 dynamic registration form submissions.
 * Represents the service selections and session data submitted by an administrator during tool registration.
 *
 * @property services - Optional array of LTI Advantage services the admin chooses to enable:
 *   - 'ags': Assignment and Grade Services for grade passback
 *   - 'nrps': Names and Role Provisioning Services for roster access
 *   - 'deep_linking': Deep Linking for content selection
 *   - 'tool_settings': Tool Settings service for configuration storage
 *   - 'basic_outcome': Basic Outcome service for simple grade reporting
 * @property sessionToken - Security token to validate the registration session and prevent CSRF attacks
 *
 * @example
 * ```typescript
 * const formData = {
 *   services: ['ags', 'nrps', 'deep_linking'],
 *   sessionToken: 'uuid-session-token'
 * };
 * const validated = DynamicRegistrationFormSchema.parse(formData);
 * ```
 */
export const DynamicRegistrationFormSchema = z.object({
  services: z
    .preprocess(
      (value) => {
        if (typeof value === 'string') {
          return [value];
        }
        return value;
      },
      z.array(z.enum(['ags', 'nrps', 'deep_linking', 'tool_settings', 'basic_outcome'])),
    )
    .optional(),
  sessionToken: z.string(),
});

export type DynamicRegistrationForm = z.infer<typeof DynamicRegistrationFormSchema>;
