import { DbModelStatus } from 'kalmia-sql-lib';
import { AuthDbTables } from '../../config/types';

export async function upgrade(queryFn: (query: string, values?: any[]) => Promise<any[]>): Promise<void> {
  await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${AuthDbTables.TOKENS}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`status\` INT NOT NULL DEFAULT '${DbModelStatus.ACTIVE}',
    \`token\` VARCHAR(500) UNIQUE NULL,
    \`user_id\` INT NULL,
    \`subject\` VARCHAR(45) NOT NULL,
    \`expiresAt\` DATETIME NULL,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`id\`),
    INDEX \`fk_token_user1_idx\` (\`user_id\` ASC),
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
