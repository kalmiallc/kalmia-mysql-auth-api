"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downgrade = exports.upgrade = void 0;
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
    ALTER TABLE \`${types_1.AuthDbTables.USERS}\` 
    MODIFY COLUMN \`email\` VARCHAR(255) NULL,
    MODIFY COLUMN \`username\` VARCHAR(50) NOT NULL,
    DROP INDEX \`email\`,
    DROP INDEX \`username\`
  `);
}
exports.upgrade = upgrade;
async function downgrade(queryFn) {
    await queryFn(`
    ALTER TABLE \`${types_1.AuthDbTables.USERS}\` 
    MODIFY COLUMN \`email\` VARCHAR(255) NULL,
    MODIFY COLUMN \`username\` VARCHAR(50) NOT NULL
  `);
}
exports.downgrade = downgrade;
//# sourceMappingURL=6-non-unique-user-email-and-username.js.map