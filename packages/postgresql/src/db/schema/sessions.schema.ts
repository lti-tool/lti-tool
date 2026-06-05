// oxlint-disable typescript/explicit-function-return-type
import type { LTISession } from '@lti-tool/core';
import { type pgTable, index, jsonb, timestamp, uuid } from 'drizzle-orm/pg-core';

export function buildSessionsTable(buildTable: typeof pgTable) {
  return buildTable(
    'sessions',
    {
      id: uuid('id').primaryKey().defaultRandom(),
      data: jsonb('data').$type<Omit<LTISession, 'id'>>().notNull(),
      expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
    },
    (table) => [index('sessions_expires_at_idx').on(table.expiresAt)],
  );
}
