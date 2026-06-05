// oxlint-disable typescript/explicit-function-return-type
import {
  type pgTable,
  index,
  text,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

export function buildClientsTable(buildTable: typeof pgTable) {
  return buildTable(
    'clients',
    {
      id: uuid('id').primaryKey().defaultRandom(),
      name: varchar('name', { length: 255 }).notNull(),
      iss: varchar('iss', { length: 255 }).notNull(),
      clientId: varchar('client_id', { length: 255 }).notNull(),
      authUrl: text('auth_url').notNull(),
      tokenUrl: text('token_url').notNull(),
      jwksUrl: text('jwks_url').notNull(),
    },
    (table) => [
      index('issuer_client_idx').on(table.clientId, table.iss),
      uniqueIndex('iss_client_id_unique').on(table.iss, table.clientId),
    ],
  );
}
