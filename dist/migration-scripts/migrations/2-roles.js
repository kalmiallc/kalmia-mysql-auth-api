"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.upgrade = upgrade;
exports.downgrade = downgrade;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.ROLES}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`status\` INT NOT NULL DEFAULT '${kalmia_sql_lib_1.DbModelStatus.ACTIVE}',
    \`name\` VARCHAR(100) NOT NULL UNIQUE,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`id\`));
  `);
}
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.ROLES}\`;
  `);
}
//# sourceMappingURL=2-roles.js.map