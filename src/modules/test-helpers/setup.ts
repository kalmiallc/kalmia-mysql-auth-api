import { Migrations, MySqlConnManager } from 'kalmia-sql-lib';
import * as mysql from 'mysql2/promise';
import * as path from 'path';

// dotenv.config({ path: '.env.testing' });

/**
 * Default stage object.
 * Import this object to gain access to application context after calling one of the init functions.
 */

export const connectToDb = async (): Promise<mysql.Pool | mysql.Connection> => {
  const dbConn = await MySqlConnManager.getInstance().getConnection();
  const migPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');
  const migs = new Migrations();
  await migs.init({
    path: migPath,
    tableName: 'auth_migrations',
    silent: true,
  });
  await migs.setup();
  return dbConn;
};

/**
 * Closes database connection.
 */
export const closeConnectionToDb = async (): Promise<void> => {
  await MySqlConnManager.getInstance().end();
};

/**
 * Cleans database.
 */
export const cleanDatabase = async (): Promise<void> => {
  const migPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');
  const migs = new Migrations();
  await migs.init({
    path: migPath,
    tableName: 'auth_migrations',
    silent: true,
  });
  await migs.clear();
};
