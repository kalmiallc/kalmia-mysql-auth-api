import { MySqlConnManager } from 'kalmia-sql-lib';
import * as mysql from 'mysql2/promise';
import * as path from 'path';
import { Migrations } from './migrations';

/**
 * Connects to database.
 * @returns Database connection.
 */
export const connectToDb = async (): Promise<mysql.Pool | mysql.Connection> => {
  const conn = await MySqlConnManager.getInstance().getConnection();
  const migrationsPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');

  const migrations = new Migrations();
  await migrations.init({
    path: migrationsPath,
    tableName: 'auth_migrations',
    silent: true
  });
  await migrations.setup();

  return conn;
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
  const migrationsPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');

  const migrations = new Migrations();
  await migrations.init({
    path: migrationsPath,
    tableName: 'auth_migrations',
    silent: true
  });
  await migrations.clear();
};
