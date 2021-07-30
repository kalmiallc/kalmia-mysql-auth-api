import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.TOKENS}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`token\` VARCHAR(500) NULL,
    \`status\` INT NOT NULL DEFAULT 5,
    \`user_id\` INT NULL,
    \`subject\` VARCHAR(45) NOT NULL,
    \`expiresAt\` DATETIME NULL,
    \`_createdAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_updatedAt\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_deletedAt\` DATETIME NULL,
    PRIMARY KEY (\`id\`),
    INDEX \`fk_token_user1_idx\` (\`user_id\` ASC) VISIBLE,
    UNIQUE INDEX \`token_UNIQUE\` (\`token\` ASC) VISIBLE,
    CONSTRAINT \`fk_token_user1\`
      FOREIGN KEY (\`user_id\`)
      REFERENCES \`${AuthDbTables.USERS}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}

export async function downgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
    DROP TABLE IF EXISTS \`${AuthDbTables.TOKENS}\`;
  `);
}
