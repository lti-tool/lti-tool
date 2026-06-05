import type { Logger } from 'pino';

export interface PostgresStorageConfig {
  logger?: Logger;
  /**
   * PostgreSQL connection URL in format: postgresql://user:password@host:port/database
   * Compatible with DATABASE_URL environment variable used by most ORMs
   */
  connectionUrl: string;
  /**
   * Optional postgres.js connection options
   */
  poolOptions?: {
    /**
     * Maximum number of connections in the pool.
     * Defaults to 1 in serverless environments, 10 otherwise.
     *
     * Recommended values:
     * - Serverless (Lambda, Cloud Functions): 1
     * - Low traffic servers: 5-10
     * - Medium traffic servers: 10-20
     * - High traffic servers: 20-50
     */
    max?: number;
    /**
     * Idle timeout in seconds before a connection is closed.
     * Defaults to 20 seconds.
     */
    idleTimeout?: number;
  };
  /**
   * Nonce expiration time in seconds (defaults to 600 = 10 minutes)
   */
  nonceExpirationSeconds?: number;
  /**
   * PostgreSQL schema name for LTI tables (e.g. 'lti', 'app').
   * Defaults to the connection's search_path (typically 'public').
   */
  schema?: string;
}
