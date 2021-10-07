"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.insertAuthUser = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const auth_user_model_1 = require("../auth-user/models/auth-user.model");
/**
 * Inserts new auth user into database.
 * @returns Created auth user.
 */
async function insertAuthUser() {
    const user = new auth_user_model_1.AuthUser({}).fake();
    const res = await user.create();
    return res.serialize(kalmia_sql_lib_1.SerializeFor.PROFILE);
}
exports.insertAuthUser = insertAuthUser;
//# sourceMappingURL=test-user.js.map