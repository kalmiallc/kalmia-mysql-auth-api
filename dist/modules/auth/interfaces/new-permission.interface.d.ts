import { PermissionLevel } from '../../../config/types';
/**
 * New permission definition interface.
 */
export interface INewPermission {
    permission_id: number;
    name: string;
    read: PermissionLevel;
    write: PermissionLevel;
    execute: PermissionLevel;
}
//# sourceMappingURL=new-permission.interface.d.ts.map