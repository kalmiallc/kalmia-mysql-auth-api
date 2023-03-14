import * as mysql from 'mysql2/promise';
/**
 * Connects to database.
 * @returns Database connection.
 */
export declare const connectToDb: () => Promise<mysql.Pool | mysql.Connection>;
/**
 * Closes database connection.
 */
export declare const closeConnectionToDb: () => Promise<void>;
/**
 * Cleans database.
 */
export declare const cleanDatabase: () => Promise<void>;
//# sourceMappingURL=setup.d.ts.map