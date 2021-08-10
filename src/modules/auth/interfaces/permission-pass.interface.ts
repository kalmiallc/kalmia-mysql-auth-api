import { PermissionLevel, PermissionType } from '../../../config/types';

/**
 * Permission pass definition interface.
 */
export interface PermissionPass {
  permission: number;
  type: PermissionType;
  level?: PermissionLevel;
}
