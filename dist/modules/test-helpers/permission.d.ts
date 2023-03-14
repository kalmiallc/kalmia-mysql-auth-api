import { Role } from '../auth-user/models/role.model';
import { INewPermission } from '../auth/interfaces/new-permission.interface';
/**
 * Inserts role and its given permissions.
 * @param roleName Name of the new role.
 * @param permissions List of permissions to add to the new role.
 * @returns Newly created role.
 */
export declare function insertRoleWithPermissions(roleName: string, permissions: INewPermission[]): Promise<Role>;
//# sourceMappingURL=permission.d.ts.map