import * as z from 'zod';

/**
 * Schema for individual member in NRPS response
 */
export const NRPSMemberResponseSchema = z.object({
  status: z.string(),
  name: z.string(),
  picture: z.url().optional(),
  given_name: z.string().optional(),
  family_name: z.string().optional(),
  middle_name: z.string().optional(),
  email: z.string().optional(), // Platforms don't force email regexp conformance
  user_id: z.string(),
  lis_person_sourcedid: z.string().optional(),
  roles: z.array(z.string()),
});

/**
 * Schema for context information in NRPS response
 */
export const NRPSContextResponseSchema = z.object({
  id: z.string(),
  label: z.string().optional(),
  title: z.string().optional(),
});

/**
 * Schema for full NRPS context membership response
 */
export const NRPSContextMembershipResponseSchema = z.object({
  id: z.url(),
  context: NRPSContextResponseSchema,
  members: z.array(NRPSMemberResponseSchema),
});

/**
 * Clean public API schemas (camelCase for JS/TS consumers)
 */
export const MemberSchema = z.object({
  status: z.string(),
  name: z.string(),
  picture: z.url().optional(),
  givenName: z.string().optional(),
  familyName: z.string().optional(),
  middleName: z.string().optional(),
  email: z.string().optional(), // Platforms don't force email regexp conformance
  userId: z.string(),
  lisPersonSourcedId: z.string().optional(),
  roles: z.array(z.string()),
});

// Export clean types for public API
export type Member = z.infer<typeof MemberSchema>;
export type Context = z.infer<typeof NRPSContextResponseSchema>;
