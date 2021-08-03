import { PermissionPass } from '../../auth-user/decorators/permission.decorator';
import { IAuthUser } from '../../auth-user/interfaces/auth-user.interface';
import { AuthUser } from '../../auth-user/models/auth-user.model';
import { RolePermission } from '../../auth-user/models/role-permission.model';
import { Role } from '../../auth-user/models/role.model';
import { IAuthResponse } from './auth-response.interface';
import { INewPermission } from './new-permission.interface';

export interface IAuth {
  /**
   * Should return filtered and paginated users.
   *
   * @param filter
   * @param params
   */
  getAuthUsers(filter: any, params: any): Promise<IAuthResponse<AuthUser[]>>;

  /**
   * Should return user by id.
   *
   * @param id
   */

  getAuthUserById(id: number): Promise<IAuthResponse<AuthUser>>;

  /**
   * Should return user by email.
   *
   * @param email
   */

  getAuthUserByEmail(email: string): Promise<IAuthResponse<AuthUser>>;

  /**
   * Should grant user roles if not already present.
   *
   * @param userId
   */
  grantRoles(roles: string[], userId: number): Promise<IAuthResponse<Role[]>>;

  /**
   * Should revoke user's roles if present.
   *
   * @param userId
   */
  revokeRoles(roles: string[], userId: number): Promise<IAuthResponse<Role[]>>;

  /**
   * Should get user's roles.
   *
   * @param userId
   */
  getAuthUserRoles(userId: number): Promise<IAuthResponse<Role[]>>;

  /**
   * Should return user's roles.
   *
   * @param id
   */
  getAuthUserPermissions(userId: any): Promise<IAuthResponse<RolePermission[]>>;

  /**
   * Should generate token with provided data and expiration and save it to DB.
   *
   * @param data
   * @param exp
   */
  generateToken(data: any, subject: string, userId?: number, exp?: any): Promise<IAuthResponse<string>>;

  /**
   * Should invalidate token in DB.
   *
   * @param token
   */
  invalidateToken(token: string): Promise<IAuthResponse<boolean>>;

  /**
   * Should check token validity and return payload.
   *
   * @param token
   */
  validateToken(token: string, subject: string): Promise<IAuthResponse<any>>;

  /**
   * Should return token with same content but refreshed expiration.
   *
   * @param id
   */
  refreshToken(token: string): Promise<IAuthResponse<string>>;

  createRole(name: string): Promise<IAuthResponse<Role>>;
  deleteRole(name: string): Promise<IAuthResponse<boolean>>;

  addPermissionsToRole(role: string, permissions: INewPermission[]): Promise<IAuthResponse<RolePermission[]>>;
  removePermissionsFromRole(role: string, permissions: number[]): Promise<IAuthResponse<RolePermission[]>>;
  getRolePermissions(role: string): Promise<IAuthResponse<RolePermission[]>>;

  loginEmail(email: string, pwd: string): Promise<IAuthResponse<string>>;
  createAuthUser(data: IAuthUser): Promise<IAuthResponse<AuthUser>>;
  deleteAuthUser(userId: any): Promise<IAuthResponse<AuthUser>>;
  canAccess(userId: any, permissions: PermissionPass[]): Promise<IAuthResponse<boolean>>;
}

