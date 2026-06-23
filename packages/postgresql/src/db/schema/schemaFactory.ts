import { pgSchema, pgTable } from 'drizzle-orm/pg-core';

import { buildClientsTable } from './clients.schema.js';
import { buildDeploymentsTable } from './deployments.schema.js';
import { buildNoncesTable } from './nonces.schema.js';
import { buildRegistrationSessionsTable } from './registrationSessions.schema.js';
import { buildSessionsTable } from './sessions.schema.js';

export type LtiSchema = {
  clientsTable: ReturnType<typeof buildClientsTable>;
  deploymentsTable: ReturnType<typeof buildDeploymentsTable>;
  noncesTable: ReturnType<typeof buildNoncesTable>;
  sessionsTable: ReturnType<typeof buildSessionsTable>;
  registrationSessionsTable: ReturnType<typeof buildRegistrationSessionsTable>;
};

export function createLtiSchema(schemaName?: string): LtiSchema {
  // When a custom schema name is provided, use pgSchema().table so Drizzle
  // qualifies all queries with that schema (e.g. "lti"."clients"). Otherwise
  // fall back to pgTable which defers to the connection's search_path.
  const buildTable: typeof pgTable = schemaName
    ? (pgSchema(schemaName).table as unknown as typeof pgTable)
    : pgTable;

  const clientsTable = buildClientsTable(buildTable);
  return {
    clientsTable,
    deploymentsTable: buildDeploymentsTable(buildTable, clientsTable),
    noncesTable: buildNoncesTable(buildTable),
    sessionsTable: buildSessionsTable(buildTable),
    registrationSessionsTable: buildRegistrationSessionsTable(buildTable),
  };
}
