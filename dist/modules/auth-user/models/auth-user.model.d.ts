import { PoolConnection } from 'mysql2/promise';
import { Role } from './role.model';
import { RolePermission } from './role-permission.model';
import { BaseModel } from 'kalmia-sql-lib';
import { AuthDbTables } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
/**
 * Auth user model.
 */
export declare class AuthUser extends BaseModel {
    /**
     * Auth user table.
     */
    tableName: AuthDbTables;
    /**
     * Auth user's id property definition
     */
    id: number;
    /**
     * Auth user's status property definition
     */
    status: number;
    /**
     * Auth user's username property definition
     */
    username: string;
    /**
     * Auth user's email property definition.
     */
    email: string;
    /**
     * Auth user's password hash property definition.
     */
    passwordHash: string;
    /**
     * Auth user's PIN property definition.
     */
    PIN: string;
    /**
     * Auth user's roles property definition.
     */
    roles: Role[];
    /**
     * Auth user's permissions property definition
     */
    permissions: RolePermission[];
    /**
     * Tells if the provided password is valid.
     *
     * @param password User password.
     */
    comparePassword(password: string): Promise<boolean>;
    /**
     * Sets user model's password hash. Does not update database entry on its own.
     *
     * @param password User password
     */
    setPassword(password: string): void;
    /**
     * Populates model fields by email.
     *
     * @param email User's email.
     */
    populateByEmail(email: string, populateRoles?: boolean): Promise<this>;
    /**
     * Populates model fields by username.
     *
     * @param username User's username.
     */
    populateByUsername(username: string, populateRoles?: boolean): Promise<this>;
    /**
     * Populates model fields by PIN number.
     *
     * @param pin User's PIN number.
     */
    populateByPin(pin: string, populateRoles?: boolean): Promise<this>;
    /**
     * Populates model fields by id.
     *
     * @param id User's id.
     */
    populateById(id: number, populateRoles?: boolean): Promise<this>;
    /**
     * Tells whether user has all the provided permissions.
     * @param permissionPasses Array of permission passed that are required of the user.
     * @returns boolean, whether user has all the permissions or not
     */
    hasPermissions(permissionPasses: PermissionPass[]): Promise<boolean>;
    /**
     * Adds role to the user.
     *
     * @param roleId Role's id.
     */
    addRole(roleId: number, conn?: PoolConnection, populateRoles?: boolean): Promise<AuthUser>;
    /**
     * Returns true if user has provided role, false otherwise.
     * @param roleId id of the role in question
     * @param conn (optional) database connection
     */
    hasRole(roleId: number, conn?: PoolConnection): Promise<boolean>;
    /**
     * Populates user's roles and their role permissions.
     * @param conn (optional) database connection
     * @returns the same instance of the object, but with the roles freshly populated.
     */
    populateRoles(conn?: PoolConnection): Promise<AuthUser>;
    /**
     * Populates user's permissions with their aggregated role permissions.
     * @param conn (optional) database connection
     * @returns same instance of user, but with permissions freshly populated
     */
    populatePermissions(conn?: PoolConnection): Promise<AuthUser>;
    /**
     * Updates fields that are not updatable with the update method.
     * @param updateFields List of fields to update
     * @returns AuthUser (this)
     */
    updateNonUpdatableFields(updateFields: string[], connection?: PoolConnection): Promise<this>;
    /**
     * Saves model data in the database as a new document.
     */
    create(options?: {
        conn?: PoolConnection;
    }): Promise<this>;
    /**
     * Revokes specified roles from user.
     * @param roleIds Role IDs.
     * @param conn (optional) Database connection.
     * @returns AuthUser (this)
     */
    revokeRoles(roleIds: number[], connection?: PoolConnection): Promise<this>;
}
//# sourceMappingURL=auth-user.model.d.ts.map