"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.upgrade = upgrade;
exports.downgrade = downgrade;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.ROLE_PERMISSIONS}\` (
    \`role_id\` INT NOT NULL,
    \`permission_id\` INT NOT NULL,
    \`name\` VARCHAR(100) NOT NULL,
    \`status\` INT NOT NULL DEFAULT '${kalmia_sql_lib_1.DbModelStatus.ACTIVE}',
    \`read\` INT NOT NULL DEFAULT 0,
    \`write\` INT NOT NULL DEFAULT 0,
    \`execute\` INT NOT NULL DEFAULT 0,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`role_id\`, \`permission_id\`),
    INDEX \`fk_role_has_permission_role1_idx\` (\`role_id\` ASC),
    CONSTRAINT \`fk_role_has_permission_role1\`
      FOREIGN KEY (\`role_id\`)
      REFERENCES \`${types_1.AuthDbTables.ROLES}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.ROLE_PERMISSIONS}\`;
  `);
}
//# sourceMappingURL=4-role-permissions.js.map