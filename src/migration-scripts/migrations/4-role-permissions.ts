import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.ROLE_PERMISSIONS}\` (
    \`role_id\` INT NOT NULL,
    \`permission_id\` INT NOT NULL,
    \`read\` INT NOT NULL DEFAULT 0,
    \`write\` INT NOT NULL DEFAULT 0,
    \`execute\` INT NOT NULL DEFAULT 0,
    \`_createdAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_updatedAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_deletedAt\` DATETIME NULL,
    PRIMARY KEY (\`role_id\`, \`permission_id\`),
    INDEX \`fk_role_has_permission_role1_idx\` (\`role_id\` ASC) VISIBLE,
    CONSTRAINT \`fk_role_has_permission_role1\`
      FOREIGN KEY (\`role_id\`)
      REFERENCES \`${AuthDbTables.ROLES}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.ROLE_PERMISSIONS}\`;
  `);
}
