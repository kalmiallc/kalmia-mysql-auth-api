import 'reflect-metadata';
// import { SetMetadata } from '@nestjs/common';
import { PermissionLevel, PermissionType } from '../../../config/types';

export interface PermissionPass {
  permission: string;
  type: PermissionType;
  level?: PermissionLevel;
}

export const PERMISSION_KEY = 'permissions';

// export const Permissions = (...permissions: Array<PermissionPass>) =>
//   SetMetadata(PERMISSION_KEY, permissions);
export const Permissions = (...permissions: PermissionPass[]) =>
  Reflect.metadata(PERMISSION_KEY, permissions);
