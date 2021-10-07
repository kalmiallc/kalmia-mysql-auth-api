import { AuthUser } from '../..';
import { AuthJwtTokenType } from '../../config/types';
import { IAuthUser } from '../auth-user/interfaces/auth-user.interface';
import { RolePermission } from '../auth-user/models/role-permission.model';
import { Role } from '../auth-user/models/role.model';
import { IAuthResponse, INewPermission, IUpdatePermission, PermissionPass } from './interfaces';
/**
 * Authorization service.
 */
export declare class Auth {
    /**
     * Class instance so it can be used as singleton.
     */
    private static instance;
    /**
     * Gets instance of the Auth class. Should initialize singleton if it doesn't exist already.
     * @returns instance of Auth
     */
    static getInstance(): Auth;
    /**
     * Gets auth user by user id.
     * @param userId if of user to search by
     * @returns AuthUser with matching id
     */
    getAuthUserById(userId: number): Promise<IAuthResponse<AuthUser>>;
    /**
     * Gets auth user by user email.
     * @param email if of user to search by
     * @returns AuthUser with matching email
     */
    getAuthUserByEmail(email: string): Promise<IAuthResponse<AuthUser>>;
    /**
     * Add chosen roles to the user.
     * @param roleIds List of role IDs.
     * @param userId User's ID.
     * @returns Updated user.
     */
    grantRoles(roleIds: number[], userId: number): Promise<IAuthResponse<AuthUser>>;
    /**
     * Removes roles from user.
     * @param roleIds Array of role IDs to remove from user.
     * @param userId Id of the user the roles should be removed from
     * @returns updated user roles
     */
    revokeRoles(roleIds: number[], userId: number): Promise<IAuthResponse<AuthUser>>;
    /**
     * Returns user's roles
     * @param userId id of user in question
     * @returns array of user roles
     */
    getAuthUserRoles(userId: number): Promise<IAuthResponse<Role[]>>;
    /**
     * Returns user's role permissions
     * @param userId id of user in question
     * @returns User's role permissions
     */
    getAuthUserPermissions(userId: any): Promise<IAuthResponse<RolePermission[]>>;
    /**
     * Generates a JWT with the provided data as payload and subject as subject.
     * @param data JWT payload
     * @param subject JWT subject
     * @param userId (optional) id of the user token is connected to, if it is connected to a user.
     * @param exp (optional) how long until the newly generated token expires, defaults to '1d'
     * @returns JWT
     */
    generateToken(data: any, subject: string, userId?: number, exp?: any): Promise<IAuthResponse<string>>;
    /**
     * Invalidates the provided token in the database.
     * @param token Token to be invalidated
     * @returns boolean, whether invalidation was successful
     */
    invalidateToken(tokenString: string): Promise<IAuthResponse<boolean>>;
    /**
     * Invalidates all of the given user's tokens with specified type.
     * @param userId User's ID.
     * @param type Type of the token.
     * @returns Boolean, whether invalidation was successful.
     */
    invalidateUserTokens(userId: number, type: AuthJwtTokenType): Promise<IAuthResponse<boolean>>;
    /**
     * Validates token. If valid, returns token payload.
     * @param token token to be validated
     * @param subject JWT subject for token to be validated with
     * @param userId User's ID - if present the ownership of the token will also be validated.
     * @returns token payload
     */
    validateToken(tokenString: string, subject: string, userId?: any): Promise<IAuthResponse<any>>;
    /**
     * Refreshes provided token if it is valid.
     * @param tokenString Token to be refreshed.
     * @returns Refreshed token.
     */
    refreshToken(tokenString: string): Promise<IAuthResponse<string>>;
    /**
     * Creates a new role, provided one with the same name doesn't already exist.
     * @param name Name of the new role.
     * @returns Newly created role.
     */
    createRole(name: string): Promise<IAuthResponse<Role>>;
    /**
     * Deletes a role. Also deletes it from all users and removes all the role's permissions.
     * @param roleId ID of the role to be deleted.
     * @returns Deleted role.
     */
    deleteRole(roleId: number): Promise<IAuthResponse<Role>>;
    /**
     * Adds role permissions to a role.
     * @param roleId Role's ID.
     * @param permissions Array of permission to be granted.
     * @returns Role with updated permissions.
     */
    addPermissionsToRole(roleId: number, permissions: INewPermission[]): Promise<IAuthResponse<Role>>;
    /**
     * Updates role permissions.
     * @param roleId Role's ID.
     * @param permissions List of permission to be updated.
     * @returns Updated role and its permissions.
     */
    updateRolePermissions(roleId: number, permissions: IUpdatePermission[]): Promise<IAuthResponse<Role>>;
    /**
     * Removes given permission from the role.
     * @param roleId Role's ID.
     * @param permissionIds List of permission IDs.
     * @returns Updated role.
     */
    removePermissionsFromRole(roleId: number, permissionIds: number[]): Promise<IAuthResponse<Role>>;
    /**
     * Return role's permissions.
     * @param roleId Role ID.
     * @returns List of role's permissions.
     */
    getRolePermissions(roleId: number): Promise<IAuthResponse<RolePermission[]>>;
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * @param email User's email
     * @param password User's password
     * @returns Authentication JWT
     */
    loginEmail(email: string, password: string): Promise<IAuthResponse<string>>;
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * @param username User's username
     * @param password User's password
     * @returns Authentication JWT
     */
    loginUsername(username: string, password: string): Promise<IAuthResponse<string>>;
    /**
     * Validates user's login credentials. If accepted, returns authentication JWT.
     * This function should be limited by the origin calling function by user's permissions.
     *
     * @param pin User's PIN number.
     * @returns Authentication JWT
     */
    loginPin(pin: string): Promise<IAuthResponse<string>>;
    /**
     * Creates auth user with provided data.
     *
     * @param data Auth user data.
     * @returns AuthUser.
     */
    createAuthUser(data: IAuthUser): Promise<IAuthResponse<AuthUser>>;
    /**
     * Marks auth user as deleted
     * @param userId id of auth user to be deleted
     * @returns updated auth user with deleted status
     */
    deleteAuthUser(userId: any): Promise<IAuthResponse<AuthUser>>;
    /**
     * Tells whether a user has requested permissions.
     * @param userId id of user to check
     * @param permissions permission to check for
     * @returns boolean, whether user has all required permissions.
     */
    canAccess(userId: any, permissions: PermissionPass[]): Promise<IAuthResponse<boolean>>;
    /**
     * Changes user's password.
     * @param userId User's ID
     * @param password User's current password.
     * @param newPassword User's new password.
     * @param force
     * @returns
     */
    changePassword(userId: any, password: string, newPassword: string, force?: boolean): Promise<IAuthResponse<AuthUser>>;
    /**
     * Updates user's email.
     * @param userId User's ID.
     * @param email User's new email.
     * @returns Updated auth user.
     */
    changeEmail(userId: any, email: string): Promise<IAuthResponse<AuthUser>>;
    /**
     * Updates user's username.
     * @param userId User's ID.
     * @param username User's new username.
     * @returns Updated auth user.
     */
    changeUsername(userId: any, username: string): Promise<IAuthResponse<AuthUser>>;
    /**
     * Updates user's username and email fields.
     * @param userId User's ID.
     * @param data User's updatable data.
     * @returns Updated auth user.
     */
    updateAuthUser(userId: any, data: {
        username: string;
        email: string;
    }): Promise<IAuthResponse<AuthUser>>;
}
//# sourceMappingURL=auth.d.ts.map