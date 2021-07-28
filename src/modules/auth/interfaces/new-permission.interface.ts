import { PermissionLevel } from '../../../config/types';

export interface INewPermission {
  permission_id: number;
  read: PermissionLevel;
  write: PermissionLevel;
  execute: PermissionLevel;
}
