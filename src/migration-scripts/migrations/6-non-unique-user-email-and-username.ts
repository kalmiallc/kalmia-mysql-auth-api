import { DbModelStatus } from 'kalmia-sql-lib';
import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    ALTER TABLE \`${AuthDbTables.USERS}\` 
    MODIFY COLUMN \`email\` VARCHAR(255) NULL,
    MODIFY COLUMN \`username\` VARCHAR(50) NOT NULL,
    DROP INDEX \`email\`,
    DROP INDEX \`username\`
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    ALTER TABLE \`${AuthDbTables.USERS}\` 
    MODIFY COLUMN \`email\` VARCHAR(255) NULL,
    MODIFY COLUMN \`username\` VARCHAR(50) NOT NULL
  `);
}
