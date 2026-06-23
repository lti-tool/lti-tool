// oxlint-disable typescript/explicit-function-return-type
import type { LTIDynamicRegistrationSession } from '@lti-tool/core';
import { type pgTable, index, jsonb, timestamp, uuid } from 'drizzle-orm/pg-core';

export function buildRegistrationSessionsTable(buildTable: typeof pgTable) {
  return buildTable(
    'registration_sessions',
    {
      id: uuid('id').primaryKey().defaultRandom(),
      data: jsonb('data')
        .$type<Omit<LTIDynamicRegistrationSession, 'sessionId'>>()
        .notNull(),
      expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    },
    (table) => [index('reg_sessions_expires_at_idx').on(table.expiresAt)],
  );
}
