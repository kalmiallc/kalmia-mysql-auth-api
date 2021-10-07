"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downgrade = exports.upgrade = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.ROLES}\` (
    \`id\` INT NOT NULL AUTO_INCREMENT,
    \`status\` INT NOT NULL DEFAULT '${kalmia_sql_lib_1.DbModelStatus.ACTIVE}',
    \`name\` VARCHAR(100) NOT NULL,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`id\`),
    UNIQUE INDEX \`name_UNIQUE\` (\`name\` ASC) VISIBLE);
  `);
}
exports.upgrade = upgrade;
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.ROLES}\`;
  `);
}
exports.downgrade = downgrade;
//# sourceMappingURL=2-roles.js.map