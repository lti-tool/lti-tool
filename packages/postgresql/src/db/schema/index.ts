import { createLtiSchema } from './schemaFactory.js';

export { createLtiSchema };

export const {
  clientsTable,
  deploymentsTable,
  noncesTable,
  sessionsTable,
  registrationSessionsTable,
} = createLtiSchema();
