import { ActionOptions, BaseModel } from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { AuthDbTables, PermissionLevel } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
/**
 * Role permission model.
 */
export declare class RolePermission extends BaseModel {
    /**
     * Role permissions table.
     */
    tableName: AuthDbTables;
    /**
     * Role permission's role_id property definition.
     */
    role_id: number;
    /**
     * Role permission's permission_id property definition.
     */
    permission_id: number;
    /**
     * Role permission's name property definition.
     */
    name: string;
    /**
     * Role permission's read property definition. Represents level of read access.
     */
    read: PermissionLevel;
    /**
     * Role permission's write property definition. Represents level of write access.
     */
    write: PermissionLevel;
    /**
     * Role permission's execute property definition. Represents level of execute access.
     */
    execute: PermissionLevel;
    constructor(data: any);
    /**
     * Tells if the model represents a document stored in the database.
     */
    exists(): boolean;
    /**
     * Tells whether a role permission meets or exceeds a certain permission requirement.
     * @param pass PermissionPass permission requirement.
     * @returns boolean, whether role permission has required permission
     */
    hasPermission(pass: PermissionPass): boolean;
    /**
     * Checks whether a certain role permission exists in the db.
     * @returns Promise<boolean>
     */
    existsInDb(): Promise<boolean>;
    /**
     * Populates model fields by Role ID and Permission ID.
     * @param roleId Role's ID.
     * @param permissionId Permission's ID.
     * @param conn (optional) Database connection.
     * @returns RolePermission (this)
     */
    populateByIds(roleId: number, permissionId: number, conn?: PoolConnection): Promise<this>;
    /**
     * Updates model fields.
     * @param options Update options.
     * @returns Updated role permission (this)
     */
    update(options?: ActionOptions): Promise<this>;
}
//# sourceMappingURL=role-permission.model.d.ts.map