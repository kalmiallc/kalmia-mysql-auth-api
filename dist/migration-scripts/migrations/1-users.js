"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downgrade = exports.upgrade = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.USERS}\` (
    \`id\` INT NOT NULL,
    \`status\` INT NOT NULL DEFAULT '${kalmia_sql_lib_1.DbModelStatus.ACTIVE}',
    \`username\` VARCHAR(50) NOT NULL UNIQUE,
    \`email\` VARCHAR(255) NULL UNIQUE,
    \`passwordHash\` VARCHAR(255) NULL,
    \`PIN\` VARCHAR(4) NULL,
    \`_createTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    \`_createUser\` INT NULL,
    \`_updateTime\` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    \`_updateUser\` INT NULL,
    PRIMARY KEY (\`id\`));
  `);
}
exports.upgrade = upgrade;
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.USERS}\`;
  `);
}
exports.downgrade = downgrade;
//# sourceMappingURL=1-users.js.map