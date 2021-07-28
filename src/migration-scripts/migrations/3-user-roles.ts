import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.USER_ROLES}\` (
    \`user_id\` INT NOT NULL,
    \`role_id\` INT NOT NULL,
    PRIMARY KEY (\`user_id\`, \`role_id\`),
    INDEX \`fk_user_has_role_role1_idx\` (\`role_id\` ASC) VISIBLE,
    INDEX \`fk_user_has_role_user_idx\` (\`user_id\` ASC) VISIBLE,
    CONSTRAINT \`fk_user_has_role_user\`
      FOREIGN KEY (\`user_id\`)
      REFERENCES \`${AuthDbTables.USERS}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION,
    CONSTRAINT \`fk_user_has_role_role1\`
      FOREIGN KEY (\`role_id\`)
      REFERENCES \`${AuthDbTables.ROLES}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.USER_ROLES}\`;
  `);
}
