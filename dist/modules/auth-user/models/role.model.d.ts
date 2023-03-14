import { BaseModel } from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { AuthDbTables } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
import { RolePermission } from './role-permission.model';
/**
 * Role model.
 */
export declare class Role extends BaseModel {
    /**
     * Roles table.
     */
    tableName: AuthDbTables;
    /**
     * Role's id property definition.
     */
    id: number;
    /**
     * Role's name property definition.
     */
    name: string;
    /**
     * Role's rolePermissions property definition.
     */
    rolePermissions: RolePermission[];
    /**
     * Checks whether a role has certain permissions
     * @param pass PermissionPass to check for. Role must meet or exceed permissions.
     * @returns boolean, whether role has permission.
     */
    hasPermission(pass: PermissionPass): boolean;
    /**
     * Populates role's role permissions.
     *
     * @param conn (optional) database connection.
     * @returns Same instance with freshly populated role permissions.
     */
    populatePermissions(conn?: PoolConnection): Promise<this>;
    /**
     * Populates role fields by name.
     *
     * @param name Role's name.
     */
    populateByName(name: string): Promise<this>;
    /**
     * Populates role fields by id.
     *
     * @param id Role's id.
     */
    populateById(id: any, conn?: PoolConnection): Promise<this>;
    /**
     * Deletes role permissions from the role.
     * @param permissionIds List of role permissions.
     */
    deleteRolePermissions(permissionIds: number[]): Promise<void>;
    /**
     * Returns a list of roles based on the given filter.
     *
     * @param filter Object used for filtering.
     * @returns List of filtered roles.
     */
    getList(filter: any): Promise<{
        items: Role[];
        total: number;
    }>;
    /**
     * Hard deletes role, its role permissions and user roles from the database.
     * @param options Delete options.
     * @returns Deleted role (this).
     */
    delete(options?: {
        conn?: PoolConnection;
    }): Promise<this>;
}
//# sourceMappingURL=role.model.d.ts.map