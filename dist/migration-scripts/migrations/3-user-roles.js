"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.downgrade = exports.upgrade = void 0;
const types_1 = require("../../config/types");
async function upgrade(queryFn) {
    await queryFn(`
  CREATE TABLE IF NOT EXISTS \`${types_1.AuthDbTables.USER_ROLES}\` (
    \`user_id\` INT NOT NULL,
    \`role_id\` INT NOT NULL,
    PRIMARY KEY (\`user_id\`, \`role_id\`),
    INDEX \`fk_user_has_role_role1_idx\` (\`role_id\` ASC) VISIBLE,
    INDEX \`fk_user_has_role_user_idx\` (\`user_id\` ASC) VISIBLE,
    CONSTRAINT \`fk_user_has_role_user\`
      FOREIGN KEY (\`user_id\`)
      REFERENCES \`${types_1.AuthDbTables.USERS}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION,
    CONSTRAINT \`fk_user_has_role_role1\`
      FOREIGN KEY (\`role_id\`)
      REFERENCES \`${types_1.AuthDbTables.ROLES}\` (\`id\`)
      ON DELETE NO ACTION
      ON UPDATE NO ACTION);
  `);
}
exports.upgrade = upgrade;
async function downgrade(queryFn) {
    await queryFn(`
    DROP TABLE IF EXISTS \`${types_1.AuthDbTables.USER_ROLES}\`;
  `);
}
exports.downgrade = downgrade;
//# sourceMappingURL=3-user-roles.js.map