import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.ROLES}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`status\` INT NOT NULL DEFAULT 5,
    \`name\` VARCHAR(100) NOT NULL,
    \`_createdAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_updatedAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_deletedAt\` DATETIME NULL,
    PRIMARY KEY (\`id\`),
    UNIQUE INDEX \`name_UNIQUE\` (\`name\` ASC) VISIBLE);
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.ROLES}\`;
  `);
}
