import { RolePermission } from '../auth-user/models/role-permission.model';
import { Role } from '../auth-user/models/role.model';
import { INewPermission } from '../auth/interfaces/new-permission.interface';

/**
 * Inserts role and its given permissions.
 * @param roleName Name of the new role.
 * @param permissions List of permissions to add to the new role.
 * @returns Newly created role.
 */
export async function insertRoleWithPermissions(roleName: string, permissions: INewPermission[]): Promise<Role> {
  const role = await new Role({ name: roleName }).create();

  for (const permission of permissions) {
    const rolePerm = new RolePermission({ role_id: role.id }).populate(permission);
    if (!(await rolePerm.existsInDb())) {
      await rolePerm.create();
    }
  }

  await role.populatePermissions();
  return role;
}
