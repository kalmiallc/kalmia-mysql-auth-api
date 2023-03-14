"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downgrade = exports.upgrade = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.TOKENS}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`status\` INT NOT NULL DEFAULT '${kalmia_sql_lib_1.DbModelStatus.ACTIVE}',
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
      REFERENCES \`${types_1.AuthDbTables.USERS}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}
exports.upgrade = upgrade;
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.TOKENS}\`;
  `);
}
exports.downgrade = downgrade;
//# sourceMappingURL=5-tokens.js.map