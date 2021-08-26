import { RolePermission } from '../auth-user/models/role-permission.model';
import { Role } from '../auth-user/models/role.model';
import { INewPermission } from '../auth/interfaces/new-permission.interface';

export async function insertRoleWithPermissions(role: string, permissions: INewPermission[]) {
  const newRole = await new Role({ name: role }).create();

  for (const permission of permissions) {
    const rolePerm = new RolePermission({ role_id: newRole.id }).populate(permission);

    if (!await rolePerm.existsInDb()) {
      await rolePerm.create();
    }
  }

  await newRole.getRolePermissions();

  console.log(JSON.stringify(newRole, null, 2));

  return newRole;
}
