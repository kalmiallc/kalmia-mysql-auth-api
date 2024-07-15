"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.insertRoleWithPermissions = insertRoleWithPermissions;
const role_permission_model_1 = require("../auth-user/models/role-permission.model");
const role_model_1 = require("../auth-user/models/role.model");
/**
 * Inserts role and its given permissions.
 * @param roleName Name of the new role.
 * @param permissions List of permissions to add to the new role.
 * @returns Newly created role.
 */
async function insertRoleWithPermissions(roleName, permissions) {
    const role = await new role_model_1.Role({ name: roleName }).create();
    for (const permission of permissions) {
        const rolePerm = new role_permission_model_1.RolePermission({ role_id: role.id }).populate(permission);
        if (!(await rolePerm.existsInDb())) {
            await rolePerm.create();
        }
    }
    await role.populatePermissions();
    return role;
}
//# sourceMappingURL=permission.js.map