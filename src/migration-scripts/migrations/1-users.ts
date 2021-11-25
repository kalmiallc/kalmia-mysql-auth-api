import { DbModelStatus } from 'kalmia-sql-lib';
import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.USERS}\` (
    \`id\` INT NOT NULL,
    \`status\` INT NOT NULL DEFAULT '${DbModelStatus.ACTIVE}',
    \`username\` VARCHAR(50) NOT NULL UNIQUE,
    \`email\` VARCHAR(255) NULL UNIQUE,
    \`passwordHash\` VARCHAR(255) NULL,
    \`PIN\` VARCHAR(4) NULL,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`id\`));
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.USERS}\`;
  `);
}
