// oxlint-disable typescript/explicit-function-return-type
import {
  type pgTable,
  index,
  text,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import type { buildClientsTable } from './clients.schema.js';

export function buildDeploymentsTable(
  buildTable: typeof pgTable,
  clientsTable: ReturnType<typeof buildClientsTable>,
) {
  return buildTable(
    'deployments',
    {
      id: uuid('id').primaryKey().defaultRandom(),
      deploymentId: varchar('deployment_id', { length: 255 }).notNull(),
      name: varchar('name', { length: 255 }),
      description: text('description'),
      clientId: uuid('client_id')
        .notNull()
        .references(() => clientsTable.id),
    },
    (table) => [
      index('deployment_id_idx').on(table.deploymentId),
      uniqueIndex('client_deployment_unique').on(table.clientId, table.deploymentId),
    ],
  );
}
