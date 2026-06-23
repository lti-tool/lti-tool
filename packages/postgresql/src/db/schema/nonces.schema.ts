// oxlint-disable typescript/explicit-function-return-type
import { type pgTable, timestamp, varchar } from 'drizzle-orm/pg-core';

export function buildNoncesTable(buildTable: typeof pgTable) {
  return buildTable('nonces', {
    nonce: varchar('nonce', { length: 255 }).primaryKey(),
    expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  });
}
