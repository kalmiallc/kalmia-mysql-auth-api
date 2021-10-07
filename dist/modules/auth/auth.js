"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Auth = void 0;
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const __1 = require("../..");
const types_1 = require("../../config/types");
const role_permission_model_1 = require("../auth-user/models/role-permission.model");
const role_model_1 = require("../auth-user/models/role.model");
const token_model_1 = require("../token/token.model");
/**
 * Authorization service.
 */
class Auth {
    /**
     * Gets instance of the Auth class. Should initialize singleton if it doesn't exist already.
     * @returns instance of Auth
     */
    static getInstance() {
        if (!this.instance) {
            this.instance = new Auth();
        }
        return this.instance;
    }
    /**
     * Gets auth user by user id.
     * @param userId if of user to search by
     * @returns AuthUser with matching id
     */
    async getAuthUserById(userId) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        return {
            status: true,
            data: user
        };
    }
    /**
     * Gets auth user by user email.
     * @param email if of user to search by
     * @returns AuthUser with matching email
     */
    async getAuthUserByEmail(email) {
        const user = await new __1.AuthUser().populateByEmail(email);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        return {
            status: true,
            data: user
        };
    }
    /**
     * Add chosen roles to the user.
     * @param roleIds List of role IDs.
     * @param userId User's ID.
     * @returns Updated user.
     */
    async grantRoles(roleIds, userId) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        const sql = new kalmia_sql_lib_1.MySqlUtil(await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection());
        const conn = await sql.start();
        try {
            for (const roleId of roleIds) {
                const role = await new role_model_1.Role().populateById(roleId, conn);
                if (!role.exists()) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
                    };
                }
                if (await user.hasRole(role.id, conn)) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthBadRequestErrorCode.AUTH_USER_ROLE_ALREADY_EXISTS]
                    };
                }
                await user.addRole(role.id, conn, false);
            }
            await user.populateRoles(conn);
            await sql.commit(conn);
        }
        catch (error) {
            await sql.rollback(conn);
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: user
        };
    }
    /**
     * Removes roles from user.
     * @param roleIds Array of role IDs to remove from user.
     * @param userId Id of the user the roles should be removed from
     * @returns updated user roles
     */
    async revokeRoles(roleIds, userId) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        const sql = new kalmia_sql_lib_1.MySqlUtil(await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection());
        const conn = await sql.start();
        try {
            for (const roleId of roleIds) {
                const role = await new role_model_1.Role().populateById(roleId, conn);
                if (!role.exists()) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
                    };
                }
                if (!(await user.hasRole(role.id, conn))) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthBadRequestErrorCode.AUTH_USER_ROLE_DOES_NOT_EXISTS]
                    };
                }
            }
            await user.revokeRoles(roleIds, conn);
            await user.populateRoles(conn);
            await sql.commit(conn);
        }
        catch (error) {
            await sql.rollback(conn);
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: user
        };
    }
    /**
     * Returns user's roles
     * @param userId id of user in question
     * @returns array of user roles
     */
    async getAuthUserRoles(userId) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        await user.populateRoles();
        return {
            status: true,
            data: user.roles
        };
    }
    /**
     * Returns user's role permissions
     * @param userId id of user in question
     * @returns User's role permissions
     */
    async getAuthUserPermissions(userId) {
        if (!userId) {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
            };
        }
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        await user.populatePermissions();
        return {
            status: true,
            data: user.permissions
        };
    }
    /**
     * Generates a JWT with the provided data as payload and subject as subject.
     * @param data JWT payload
     * @param subject JWT subject
     * @param userId (optional) id of the user token is connected to, if it is connected to a user.
     * @param exp (optional) how long until the newly generated token expires, defaults to '1d'
     * @returns JWT
     */
    async generateToken(data, subject, userId, exp) {
        const token = new token_model_1.Token({
            payload: data,
            subject,
            user_id: userId
        });
        const tokenString = await token.generate(exp);
        if (tokenString) {
            return {
                status: true,
                data: tokenString
            };
        }
        return {
            status: false,
            errors: [types_1.AuthBadRequestErrorCode.DEFAULT_BAD_REQUEST_ERROR]
        };
    }
    /**
     * Invalidates the provided token in the database.
     * @param token Token to be invalidated
     * @returns boolean, whether invalidation was successful
     */
    async invalidateToken(tokenString) {
        if (!tokenString) {
            return {
                status: false,
                errors: [types_1.AuthBadRequestErrorCode.MISSING_DATA_ERROR]
            };
        }
        const token = await new token_model_1.Token({}).populateByToken(tokenString);
        const invalidation = await token.invalidateToken();
        if (invalidation) {
            return {
                status: true,
                data: invalidation
            };
        }
        return {
            status: false,
            errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR]
        };
    }
    /**
     * Invalidates all of the given user's tokens with specified type.
     * @param userId User's ID.
     * @param type Type of the token.
     * @returns Boolean, whether invalidation was successful.
     */
    async invalidateUserTokens(userId, type) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        try {
            const invalidation = await new token_model_1.Token().invalidateUserTokens(userId, type);
            if (invalidation) {
                return {
                    status: true,
                    data: invalidation
                };
            }
        }
        catch (error) {
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
    }
    /**
     * Validates token. If valid, returns token payload.
     * @param token token to be validated
     * @param subject JWT subject for token to be validated with
     * @param userId User's ID - if present the ownership of the token will also be validated.
     * @returns token payload
     */
    async validateToken(tokenString, subject, userId = null) {
        const token = new token_model_1.Token({ token: tokenString, subject });
        const validation = await token.validateToken(userId);
        if (!validation) {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.INVALID_TOKEN]
            };
        }
        return {
            status: true,
            data: validation
        };
    }
    /**
     * Refreshes provided token if it is valid.
     * @param tokenString Token to be refreshed.
     * @returns Refreshed token.
     */
    async refreshToken(tokenString) {
        if (!tokenString) {
            return {
                status: false,
                errors: [types_1.AuthBadRequestErrorCode.MISSING_DATA_ERROR]
            };
        }
        const token = new token_model_1.Token({ token: tokenString });
        const refreshedToken = await token.refresh();
        if (!refreshedToken) {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.INVALID_TOKEN]
            };
        }
        return {
            status: true,
            data: refreshedToken
        };
    }
    /**
     * Creates a new role, provided one with the same name doesn't already exist.
     * @param name Name of the new role.
     * @returns Newly created role.
     */
    async createRole(name) {
        const role = new role_model_1.Role({ name });
        try {
            await role.validate();
        }
        catch (error) {
            await role.handle(error);
        }
        if (role.isValid()) {
            try {
                await role.create();
                return {
                    status: true,
                    data: role
                };
            }
            catch (error) {
                return {
                    status: false,
                    errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                    details: error
                };
            }
        }
        else {
            return {
                status: false,
                errors: role.collectErrors().map((x) => x.code)
            };
        }
    }
    /**
     * Deletes a role. Also deletes it from all users and removes all the role's permissions.
     * @param roleId ID of the role to be deleted.
     * @returns Deleted role.
     */
    async deleteRole(roleId) {
        const role = await new role_model_1.Role().populateById(roleId);
        if (!role.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
            };
        }
        try {
            await role.delete();
        }
        catch (error) {
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: role
        };
    }
    /**
     * Adds role permissions to a role.
     * @param roleId Role's ID.
     * @param permissions Array of permission to be granted.
     * @returns Role with updated permissions.
     */
    async addPermissionsToRole(roleId, permissions) {
        const role = await new role_model_1.Role().populateById(roleId);
        if (!role.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
            };
        }
        const sql = new kalmia_sql_lib_1.MySqlUtil(await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection());
        const conn = await sql.start();
        const rolePermissions = [];
        try {
            for (const permission of permissions) {
                const rolePermission = new role_permission_model_1.RolePermission(Object.assign(Object.assign({}, permission), { role_id: role.id }));
                try {
                    await rolePermission.validate();
                }
                catch (error) {
                    await rolePermission.handle(error);
                }
                if (!rolePermission.isValid()) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: rolePermission.collectErrors().map((x) => x.code)
                    };
                }
                if (!(await rolePermission.existsInDb())) {
                    await rolePermission.create({ conn });
                    rolePermissions.push(rolePermission);
                }
                else {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthBadRequestErrorCode.ROLE_PERMISSION_ALREADY_EXISTS]
                    };
                }
            }
            await sql.commit(conn);
            role.rolePermissions = [...role.rolePermissions, ...rolePermissions];
        }
        catch (error) {
            await sql.rollback(conn);
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: role
        };
    }
    /**
     * Updates role permissions.
     * @param roleId Role's ID.
     * @param permissions List of permission to be updated.
     * @returns Updated role and its permissions.
     */
    async updateRolePermissions(roleId, permissions) {
        const role = await new role_model_1.Role().populateById(roleId);
        if (!role.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
            };
        }
        const sql = new kalmia_sql_lib_1.MySqlUtil(await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection());
        const conn = await sql.start();
        try {
            for (const permission of permissions) {
                const rolePermission = await new role_permission_model_1.RolePermission({}).populateByIds(role.id, permission.permission_id, conn);
                if (!rolePermission.exists()) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_PERMISSION_DOES_NOT_EXISTS]
                    };
                }
                rolePermission.populate(permission, kalmia_sql_lib_1.PopulateFor.PROFILE);
                try {
                    await rolePermission.validate();
                }
                catch (error) {
                    await rolePermission.handle(error);
                }
                if (!rolePermission.isValid()) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: rolePermission.collectErrors().map((x) => x.code)
                    };
                }
                await rolePermission.update({ conn });
            }
            await role.populatePermissions(conn);
            await sql.commit(conn);
        }
        catch (error) {
            await sql.rollback(conn);
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: role
        };
    }
    /**
     * Removes given permission from the role.
     * @param roleId Role's ID.
     * @param permissionIds List of permission IDs.
     * @returns Updated role.
     */
    async removePermissionsFromRole(roleId, permissionIds) {
        const role = await new role_model_1.Role().populateById(roleId);
        if (!role.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
            };
        }
        for (const permissionId of permissionIds) {
            const rolePermission = new role_permission_model_1.RolePermission({
                role_id: role.id,
                permission_id: permissionId
            });
            if (!(await rolePermission.existsInDb())) {
                return {
                    status: false,
                    errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_PERMISSION_DOES_NOT_EXISTS]
                };
            }
        }
        try {
            await role.deleteRolePermissions(permissionIds);
        }
        catch (error) {
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
        return {
            status: true,
            data: role
        };
    }
    /**
     * Return role's permissions.
     * @param roleId Role ID.
     * @returns List of role's permissions.
     */
    async getRolePermissions(roleId) {
        const role = await new role_model_1.Role().populateById(roleId);
        if (!role.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
            };
        }
        return {
            status: true,
            data: role.rolePermissions
        };
    }
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * @param email User's email
     * @param password User's password
     * @returns Authentication JWT
     */
    async loginEmail(email, password) {
        const user = await new __1.AuthUser({}).populateByEmail(email);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        if (await user.comparePassword(password)) {
            return await this.generateToken({ userId: user.id }, types_1.AuthJwtTokenType.USER_AUTHENTICATION, user.id);
        }
        else {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
            };
        }
    }
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * @param username User's username
     * @param password User's password
     * @returns Authentication JWT
     */
    async loginUsername(username, password) {
        const user = await new __1.AuthUser({}).populateByUsername(username);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        if (await user.comparePassword(password)) {
            return await this.generateToken({ userId: user.id }, types_1.AuthJwtTokenType.USER_AUTHENTICATION, user.id);
        }
        else {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
            };
        }
    }
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * This function should be limited by the origin calling function by user's permissions.
     *
     * @param pin User's PIN number.
     * @returns Authentication JWT
     */
    async loginPin(pin) {
        const user = await new __1.AuthUser({}).populateByPin(pin);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
            };
        }
        return await this.generateToken({ userId: user.id }, types_1.AuthJwtTokenType.USER_AUTHENTICATION, user.id);
    }
    /**
     * Creates auth user with provided data.
     *
     * @param data Auth user data.
     * @returns AuthUser.
     */
    async createAuthUser(data) {
        const user = new __1.AuthUser(data);
        if (data.password) {
            user.setPassword(data.password);
        }
        try {
            await user.validate();
        }
        catch (error) {
            await user.handle(error);
        }
        if (user.isValid()) {
            try {
                await user.create();
            }
            catch (error) {
                return {
                    status: false,
                    errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                    details: error
                };
            }
            return {
                status: true,
                data: user
            };
        }
        else {
            return {
                status: false,
                errors: user.collectErrors().map((x) => x.code)
            };
        }
    }
    /**
     * Marks auth user as deleted
     * @param userId id of auth user to be deleted
     * @returns updated auth user with deleted status
     */
    async deleteAuthUser(userId) {
        const user = await new __1.AuthUser().populateById(userId);
        if (!user.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        try {
            await user.delete();
            return {
                status: true,
                data: user
            };
        }
        catch (error) {
            return {
                status: false,
                errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                details: error
            };
        }
    }
    /**
     * Tells whether a user has requested permissions.
     * @param userId id of user to check
     * @param permissions permission to check for
     * @returns boolean, whether user has all required permissions.
     */
    async canAccess(userId, permissions) {
        const user = await new __1.AuthUser().populateById(userId);
        const canAccess = await user.hasPermissions(permissions);
        return {
            status: true,
            data: canAccess
        };
    }
    /**
     * Changes user's password.
     * @param userId User's ID
     * @param password User's current password.
     * @param newPassword User's new password.
     * @param force
     * @returns
     */
    async changePassword(userId, password, newPassword, force = false) {
        if (!userId || !newPassword || (!force && !password)) {
            return {
                status: false,
                errors: [types_1.AuthBadRequestErrorCode.MISSING_DATA_ERROR]
            };
        }
        const authUser = await new __1.AuthUser().populateById(userId);
        if (!authUser.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        if (force || (await authUser.comparePassword(password))) {
            authUser.setPassword(newPassword);
            try {
                await authUser.validate();
            }
            catch (error) {
                await authUser.handle(error);
            }
            if (!authUser.isValid()) {
                return {
                    status: false,
                    errors: authUser.collectErrors().map((x) => x.code)
                };
            }
            else {
                const sql = new kalmia_sql_lib_1.MySqlUtil(await kalmia_sql_lib_1.MySqlConnManager.getInstance().getConnection());
                const conn = await sql.start();
                try {
                    await authUser.updateNonUpdatableFields(['passwordHash'], conn);
                    await new token_model_1.Token().invalidateUserTokens(authUser.id, types_1.AuthJwtTokenType.USER_AUTHENTICATION, conn);
                    await sql.commit(conn);
                }
                catch (error) {
                    await sql.rollback(conn);
                    return {
                        status: false,
                        errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                        details: error
                    };
                }
                return {
                    status: true,
                    data: authUser
                };
            }
        }
        else {
            return {
                status: false,
                errors: [types_1.AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
            };
        }
    }
    /**
     * Updates user's email.
     * @param userId User's ID.
     * @param email User's new email.
     * @returns Updated auth user.
     */
    async changeEmail(userId, email) {
        if (!userId || !email) {
            return {
                status: false,
                errors: [types_1.AuthBadRequestErrorCode.MISSING_DATA_ERROR]
            };
        }
        const authUser = await new __1.AuthUser().populateById(userId);
        if (!authUser.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        authUser.populate({ email });
        try {
            await authUser.validate();
        }
        catch (error) {
            await authUser.handle(error);
        }
        if (!authUser.isValid()) {
            return {
                status: false,
                errors: authUser.collectErrors().map((x) => x.code)
            };
        }
        else {
            try {
                await authUser.updateNonUpdatableFields(['email']);
            }
            catch (error) {
                return {
                    status: false,
                    errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                    details: error
                };
            }
            return {
                status: true,
                data: authUser
            };
        }
    }
    /**
     * Updates user's username.
     * @param userId User's ID.
     * @param username User's new username.
     * @returns Updated auth user.
     */
    async changeUsername(userId, username) {
        if (!userId || !username) {
            return {
                status: false,
                errors: [types_1.AuthBadRequestErrorCode.MISSING_DATA_ERROR]
            };
        }
        const authUser = await new __1.AuthUser().populateById(userId);
        if (!authUser.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        authUser.populate({ username });
        try {
            await authUser.validate();
        }
        catch (error) {
            await authUser.handle(error);
        }
        if (!authUser.isValid()) {
            return {
                status: false,
                errors: authUser.collectErrors().map((x) => x.code)
            };
        }
        else {
            try {
                await authUser.updateNonUpdatableFields(['username']);
            }
            catch (error) {
                return {
                    status: false,
                    errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                    details: error
                };
            }
            return {
                status: true,
                data: authUser
            };
        }
    }
    /**
     * Updates user's username and email fields.
     * @param userId User's ID.
     * @param data User's updatable data.
     * @returns Updated auth user.
     */
    async updateAuthUser(userId, data) {
        const authUser = await new __1.AuthUser().populateById(userId);
        if (!authUser.exists()) {
            return {
                status: false,
                errors: [types_1.AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
            };
        }
        authUser.populate(data);
        try {
            await authUser.validate();
        }
        catch (error) {
            await authUser.handle(error);
        }
        if (!authUser.isValid()) {
            return {
                status: false,
                errors: authUser.collectErrors().map((x) => x.code)
            };
        }
        else {
            try {
                await authUser.updateNonUpdatableFields(['username', 'email']);
            }
            catch (error) {
                return {
                    status: false,
                    errors: [types_1.AuthSystemErrorCode.SQL_SYSTEM_ERROR],
                    details: error
                };
            }
            return {
                status: true,
                data: authUser
            };
        }
    }
}
exports.Auth = Auth;
//# sourceMappingURL=auth.js.map