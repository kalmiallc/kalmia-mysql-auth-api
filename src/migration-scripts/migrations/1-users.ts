import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.USERS}\` (
    \`id\` INT NOT NULL,
    \`status\` INT NOT NULL DEFAULT 5,
    \`username\` VARCHAR(50) NULL,
    \`email\` VARCHAR(255) NULL,
    \`passwordHash\` VARCHAR(255) NOT NULL DEFAULT "xasfaegklsjgkljsbdv",
    \`PIN\` VARCHAR(60) NULL,
    \`_createdAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_updatedAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_deletedAt\` DATETIME NULL,
    PRIMARY KEY (\`id\`),
    UNIQUE INDEX \`email_UNIQUE\` (\`email\` ASC) VISIBLE,
    UNIQUE INDEX \`username_UNIQUE\` (\`username\` ASC) VISIBLE);
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.USERS}\`;
  `);
}
