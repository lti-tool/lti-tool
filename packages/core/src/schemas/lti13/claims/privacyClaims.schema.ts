import * as z from 'zod';

// These claims are optional per the LTI 1.3 / OIDC spec.
export const PrivacyClaimsSchema = z.object({
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  name: z.string().optional(),
  email: z.string().optional(),
});
