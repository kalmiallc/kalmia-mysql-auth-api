"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.cleanDatabase = exports.closeConnectionToDb = exports.connectToDb = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const path = require("path");
/**
 * Connects to database.
 * @returns Database connection.
 */
const connectToDb = async () => {
    const conn = await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection();
    const migrationsPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');
    const migrations = new kalmia_sql_lib_1.Migrations();
    await migrations.init({
        path: migrationsPath,
        tableName: 'auth_migrations',
        silent: true
    });
    await migrations.setup();
    return conn;
};
exports.connectToDb = connectToDb;
/**
 * Closes database connection.
 */
const closeConnectionToDb = async () => {
    await kalmia_sql_lib_1.MySqlConnManager.getInstance().end();
};
exports.closeConnectionToDb = closeConnectionToDb;
/**
 * Cleans database.
 */
const cleanDatabase = async () => {
    const migrationsPath = path.join(__dirname, '..', '..', 'migration-scripts', 'migrations');
    const migrations = new kalmia_sql_lib_1.Migrations();
    await migrations.init({
        path: migrationsPath,
        tableName: 'auth_migrations',
        silent: true
    });
    await migrations.clear();
};
exports.cleanDatabase = cleanDatabase;
//# sourceMappingURL=setup.js.map