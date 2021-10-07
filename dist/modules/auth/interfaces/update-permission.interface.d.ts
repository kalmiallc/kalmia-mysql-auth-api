import { PermissionLevel } from '../../../config/types';
/**
 * Update permission definition interface.
 */
export interface IUpdatePermission {
    permission_id: number;
    read?: PermissionLevel;
    write?: PermissionLevel;
    execute?: PermissionLevel;
}
//# sourceMappingURL=update-permission.interface.d.ts.map