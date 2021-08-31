import { MySqlConnManager, MySqlUtil } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthUser } from '../..';
import {
  AuthAuthenticationErrorCode,
  AuthDbTables,
  AuthBadRequestErrorCode,
  AuthJwtTokenType,
  AuthResourceNotFoundErrorCode,
  AuthSystemErrorCode
} from '../../config/types';
import { PermissionPass } from './interfaces/permission-pass.interface';
import { IAuthUser } from '../auth-user/interfaces/auth-user.interface';
import { RolePermission } from '../auth-user/models/role-permission.model';
import { Role } from '../auth-user/models/role.model';
import { Token } from '../token/token.model';
import { IAuthResponse } from './interfaces/auth-response.interface';
import { INewPermission } from './interfaces/new-permission.interface';

/**
 * Authorization service.
 */
export class Auth {
  /**
   * Class instance so it can be used as singleton.
   */
  private static instance: Auth;

  /**
   * Gets instance of the Auth class. Should initialize singleton if it doesn't exist already.
   * @returns instance of Auth
   */
  public static getInstance() {
    if (!this.instance) {
      this.instance = new Auth();
    }
    return this.instance;
  }

  /**
   * Gets auth user by user id.
   * @param userId if of user to search by
   * @returns AuthUser with matching id
   */
  async getAuthUserById(userId: number): Promise<IAuthResponse<AuthUser>> {
    const user = await new AuthUser().populateById(userId);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    return {
      status: true,
      data: user
    };
  }

  /**
   * Gets auth user by user email.
   * @param email if of user to search by
   * @returns AuthUser with matching email
   */
  async getAuthUserByEmail(email: string): Promise<IAuthResponse<AuthUser>> {
    const user = await new AuthUser().populateByEmail(email);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    return {
      status: true,
      data: user
    };
  }

  /**
   * Add chosen roles to the user.
   * @param roleIds List of role IDs.
   * @param userId User's ID.
   * @returns Updated user.
   */
  async grantRoles(roleIds: number[], userId: number): Promise<IAuthResponse<AuthUser>> {
    const user = await new AuthUser().populateById(userId);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    const sql = new MySqlUtil(await MySqlConnManager.getInstance().getConnection());
    const conn = await sql.start();
    try {
      for (const roleId of roleIds) {
        const role = await new Role().populateById(roleId, conn);
        if (!role.exists()) {
          await sql.rollback(conn);

          return {
            status: false,
            errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
          };
        }
        if (await user.hasRole(role.id, conn)) {
          await sql.rollback(conn);

          return {
            status: false,
            errors: [AuthBadRequestErrorCode.AUTH_USER_ROLE_ALREADY_EXISTS]
          };
        }

        await user.addRole(role.id, conn, false);
      }

      await user.populateRoles(conn);
      await sql.commit(conn);
    } catch (error) {
      await sql.rollback(conn);

      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }

    return {
      status: true,
      data: user
    };
  }

  /**
   * Removes roles from user.
   * @param roleIds Array of role IDs to remove from user.
   * @param userId Id of the user the roles should be removed from
   * @returns updated user roles
   */
  async revokeRoles(roleIds: number[], userId: number): Promise<IAuthResponse<Role[]>> {
    const user = await new AuthUser().populateById(userId);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    const sql = new MySqlUtil(await MySqlConnManager.getInstance().getConnection());
    const conn = await sql.start();
    try {
      for (const roleId of roleIds) {
        const role = await new Role().populateById(roleId, conn);
        if (!role.exists()) {
          await sql.rollback(conn);

          return {
            status: false,
            errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
          };
        }

        if (!(await user.hasRole(role.id, conn))) {
          await sql.rollback(conn);

          return {
            status: false,
            errors: [AuthBadRequestErrorCode.AUTH_USER_ROLE_DOES_NOT_EXISTS]
          };
        }
      }

      await user.revokeRoles(roleIds, conn);
      await user.populateRoles(conn);
      await sql.commit(conn);
    } catch (error) {
      await sql.rollback(conn);

      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }

    return {
      status: true,
      data: user.roles
    };
  }

  /**
   * Returns user's roles
   * @param userId id of user in question
   * @returns array of user roles
   */
  async getAuthUserRoles(userId: number): Promise<IAuthResponse<Role[]>> {
    const user = await new AuthUser().populateById(userId);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    await user.populateRoles();
    return {
      status: true,
      data: user.roles
    };
  }

  /**
   * Returns user's role permissions
   * @param userId id of user in question
   * @returns User's role permissions
   */
  async getAuthUserPermissions(userId: any): Promise<IAuthResponse<RolePermission[]>> {
    if (!userId) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const user = await new AuthUser().populateById(userId);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    await user.populatePermissions();
    return {
      status: true,
      data: user.permissions
    };
  }

  /**
   * Generates a JWT with the provided data as payload and subject as subject.
   * @param data JWT payload
   * @param subject JWT subject
   * @param userId (optional) id of the user token is connected to, if it is connected to a user.
   * @param exp (optional) how long until the newly generated token expires, defaults to '1d'
   * @returns JWT
   */
  async generateToken(data: any, subject: string, userId?: number, exp?: any): Promise<IAuthResponse<string>> {
    const token = new Token({
      payload: data,
      subject,
      user_id: userId
    });

    const tokenString = await token.generate(exp);
    if (tokenString) {
      return {
        status: true,
        data: tokenString
      };
    }

    return {
      status: false,
      errors: [AuthBadRequestErrorCode.DEFAULT_BAD_REQUEST_ERROR]
    };
  }

  /**
   * Invalidates the provided token in the database.
   * @param token Token to be invalidated
   * @returns boolean, whether invalidation was successful
   */
  async invalidateToken(tokenString: string): Promise<IAuthResponse<boolean>> {
    if (!tokenString) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const token = await new Token({}).populateByToken(tokenString);
    const invalidation = await token.invalidateToken();
    if (invalidation) {
      return {
        status: true,
        data: invalidation
      };
    }

    return {
      status: false,
      errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR]
    };
  }

  /**
   * Validates token. If valid, returns token payload.
   * @param token token to be validated
   * @param subject JWT subject for token to be validated with
   * @param userId User's ID - if present the ownership of the token will also be validated.
   * @returns token payload
   */
  async validateToken(tokenString: string, subject: string, userId: any = null): Promise<IAuthResponse<any>> {
    const token = new Token({ token: tokenString, subject });
    const validation = await token.validateToken(userId);
    if (!validation) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.INVALID_TOKEN]
      };
    }

    return {
      status: true,
      data: validation
    };
  }

  /**
   * Refreshes provided token if it is valid.
   * @param tokenString Token to be refreshed.
   * @returns Refreshed token.
   */
  async refreshToken(tokenString: string): Promise<IAuthResponse<string>> {
    if (!tokenString) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const token = new Token({ token: tokenString });
    const refreshedToken = await token.refresh();
    if (!refreshedToken) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.INVALID_TOKEN]
      };
    }

    return {
      status: true,
      data: refreshedToken
    };
  }

  /**
   * Creates a new role, provided one with the same name doesn't already exist.
   * @param name Name of the new role.
   * @returns Newly created role.
   */
  async createRole(name: string): Promise<IAuthResponse<Role>> {
    const role = new Role({ name });
    try {
      await role.validate();
    } catch (error) {
      await role.handle(error);
    }

    if (role.isValid()) {
      try {
        await role.create();
        return {
          status: true,
          data: role
        };
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error
        };
      }
    } else {
      return {
        status: false,
        errors: role.collectErrors().map((x) => x.code)
      };
    }
  }

  /**
   * Deletes a role. Also deletes it from all users and removes all the role's permissions.
   * @param name Name of the role to delete.
   * @returns boolean, whether operation was successful
   */
  async deleteRole(name: string): Promise<IAuthResponse<boolean>> {
    const conn = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).start();
    const mySqlHelper = new MySqlUtil(conn);
    try {
      const queryUserRoles = `
        DELETE ur
        FROM ${AuthDbTables.USER_ROLES} ur
        JOIN ${AuthDbTables.ROLES} r
          ON ur.role_id = r.id
        WHERE r.name = @name
        `;
      const dataUserRoles = await mySqlHelper.paramExecute(queryUserRoles, { name }, conn);

      const queryRolePermissions = `
        DELETE rp
        FROM ${AuthDbTables.ROLE_PERMISSIONS} rp
        JOIN ${AuthDbTables.ROLES} r
          ON rp.role_id = r.id
        WHERE r.name = @name
      `;
      const dataRolePermissions = await mySqlHelper.paramExecute(queryRolePermissions, { name }, conn);

      const queryRole = `
        DELETE FROM ${AuthDbTables.ROLES}
        WHERE name = @name
      `;
      const dataRole = await mySqlHelper.paramExecute(queryRole, { name }, conn);
      await new MySqlUtil(conn).commit(conn);
    } catch (error) {
      await new MySqlUtil(conn).rollback(conn);
      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }
    return {
      status: true,
      data: true
    };
  }

  /**
   * Adds role permissions to a role.
   * @param roleId Role's ID.
   * @param permissions Array of permission to be granted.
   * @returns Role with updated permissions.
   */
  async addPermissionsToRole(roleId: number, permissions: INewPermission[]): Promise<IAuthResponse<Role>> {
    const role = await new Role().populateById(roleId);
    if (!role.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
      };
    }

    const sql = new MySqlUtil(await MySqlConnManager.getInstance().getConnection());
    const conn = await sql.start();
    const rolePermissions: RolePermission[] = [];
    try {
      for (const permission of permissions) {
        const rolePermission = new RolePermission({ role_id: role.id }).populate(permission);

        if (!(await rolePermission.existsInDb())) {
          await rolePermission.create({ conn });
          rolePermissions.push(rolePermission);
        } else {
          await sql.rollback(conn);

          return {
            status: false,
            errors: [AuthBadRequestErrorCode.ROLE_PERMISSION_ALREADY_EXISTS]
          };
        }
      }

      await sql.commit(conn);
      role.rolePermissions = [...role.rolePermissions, ...rolePermissions];
    } catch (error) {
      await sql.rollback(conn);

      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }

    return {
      status: true,
      data: role
    };
  }

  /**
   * Removes given permission from the role.
   * @param roleId Role's ID.
   * @param permissionIds List of permission IDs.
   * @returns Updated role.
   */
  async removePermissionsFromRole(roleId: number, permissionIds: number[]): Promise<IAuthResponse<Role>> {
    const role = await new Role().populateById(roleId);
    if (!role.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
      };
    }

    for (const permissionId of permissionIds) {
      const rolePermission = new RolePermission({
        role_id: role.id,
        permission_id: permissionId
      });

      if (!(await rolePermission.existsInDb())) {
        return {
          status: false,
          errors: [AuthResourceNotFoundErrorCode.ROLE_PERMISSION_DOES_NOT_EXISTS]
        };
      }
    }

    try {
      await role.deleteRolePermissions(permissionIds);
    } catch (error) {
      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }

    return {
      status: true,
      data: role
    };
  }

  /**
   * Return role's permissions.
   * @param roleId Role ID.
   * @returns List of role's permissions.
   */
  async getRolePermissions(roleId: number): Promise<IAuthResponse<RolePermission[]>> {
    const role = await new Role().populateById(roleId);
    if (!role.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
      };
    }

    return {
      status: true,
      data: role.rolePermissions
    };
  }

  /**
   * Validates user's login credentials. If accepted, returns authentication JWT.
   * @param email User's email
   * @param password User's password
   * @returns Authentication JWT
   */
  async loginEmail(email: string, password: string): Promise<IAuthResponse<string>> {
    const user: AuthUser = await new AuthUser({}).populateByEmail(email);

    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    if (await user.comparePassword(password)) {
      return await this.generateToken({ userId: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
    } else {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
  }

  /**
   * Validates user's login credentials. If accepted, returns authentication JWT.
   * @param username User's username
   * @param password User's password
   * @returns Authentication JWT
   */
  async loginUsername(username: string, password: string): Promise<IAuthResponse<string>> {
    const user: AuthUser = await new AuthUser({}).populateByUsername(username);

    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    if (await user.comparePassword(password)) {
      return await this.generateToken({ userId: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
    } else {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
  }

  /**
   * Validates user's login credentials. If accepted, returns authentication JWT.
   * This function should be limited by the origin calling function by user's permissions.
   *
   * @param pin User's PIN number.
   * @returns Authentication JWT
   */
  async loginPin(pin: string): Promise<IAuthResponse<string>> {
    const user = await new AuthUser({}).populateByPin(pin);
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    return await this.generateToken({ userId: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
  }

  /**
   * Creates auth user with provided data.
   *
   * @param data Auth user data.
   * @returns AuthUser.
   */
  async createAuthUser(data: IAuthUser): Promise<IAuthResponse<AuthUser>> {
    const user: AuthUser = new AuthUser(data);
    if ((data as any).password) {
      user.setPassword((data as any).password);
    }

    try {
      await user.validate();
    } catch (error) {
      await user.handle(error);
    }

    if (user.isValid()) {
      try {
        await user.create();
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error
        };
      }

      return {
        status: true,
        data: user
      };
    } else {
      return {
        status: false,
        errors: user.collectErrors().map((x) => x.code)
      };
    }
  }

  /**
   * Marks auth user as deleted
   * @param userId id of auth user to be deleted
   * @returns updated auth user with deleted status
   */
  async deleteAuthUser(userId: any): Promise<IAuthResponse<AuthUser>> {
    try {
      const user = await new AuthUser().populateById(userId);
      await user.delete();

      return {
        status: true,
        data: user
      };
    } catch (error) {
      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error
      };
    }
  }

  /**
   * Tells whether a user has requested permissions.
   * @param userId id of user to check
   * @param permissions permission to check for
   * @returns boolean, whether user has all required permissions.
   */
  async canAccess(userId: any, permissions: PermissionPass[]): Promise<IAuthResponse<boolean>> {
    const user: AuthUser = await new AuthUser().populateById(userId);
    const canAccess = await user.hasPermissions(permissions);
    return {
      status: true,
      data: canAccess
    };
  }

  /**
   * Changes user's password.
   * @param userId User's ID
   * @param password User's current password.
   * @param newPassword User's new password.
   * @param force
   * @returns
   */
  async changePassword(userId: any, password: string, newPassword: string, force: boolean = false): Promise<IAuthResponse<AuthUser>> {
    if (!userId || !newPassword || (!force && !password)) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const authUser = await new AuthUser().populateById(userId);
    if (!authUser.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    if (force || (await authUser.comparePassword(password))) {
      authUser.setPassword(newPassword);
      try {
        await authUser.validate();
      } catch (error) {
        await authUser.handle(error);
      }

      if (!authUser.isValid()) {
        return {
          status: false,
          errors: authUser.collectErrors().map((x) => x.code)
        };
      } else {
        try {
          await authUser.updateNonUpdatableFields(['passwordHash']);
        } catch (error) {
          return {
            status: false,
            errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
            details: error
          };
        }

        return {
          status: true,
          data: authUser
        };
      }
    } else {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
  }

  /**
   * Updates user's email.
   * @param userId User's ID.
   * @param email User's new email.
   * @returns Updated auth user.
   */
  async changeEmail(userId: any, email: string): Promise<IAuthResponse<AuthUser>> {
    if (!userId || !email) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const authUser = await new AuthUser().populateById(userId);
    if (!authUser.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    authUser.populate({ email });
    try {
      await authUser.validate();
    } catch (error) {
      await authUser.handle(error);
    }

    if (!authUser.isValid()) {
      return {
        status: false,
        errors: authUser.collectErrors().map((x) => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields(['email']);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error
        };
      }

      return {
        status: true,
        data: authUser
      };
    }
  }

  /**
   * Updates user's username.
   * @param userId User's ID.
   * @param username User's new username.
   * @returns Updated auth user.
   */
  async changeUsername(userId: any, username: string): Promise<IAuthResponse<AuthUser>> {
    if (!userId || !username) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const authUser = await new AuthUser().populateById(userId);
    if (!authUser.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    authUser.populate({ username });
    try {
      await authUser.validate();
    } catch (error) {
      await authUser.handle(error);
    }

    if (!authUser.isValid()) {
      return {
        status: false,
        errors: authUser.collectErrors().map((x) => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields(['username']);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error
        };
      }

      return {
        status: true,
        data: authUser
      };
    }
  }

  /**
   * Updates user's username and email fields.
   * @param userId User's ID.
   * @param data User's updatable data.
   * @returns Updated auth user.
   */
  async update(userId: any, data: { username: string; email: string }): Promise<IAuthResponse<AuthUser>> {
    const authUser = await new AuthUser().populateById(userId);
    if (!authUser.exists()) {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }

    authUser.populate(data);
    try {
      await authUser.validate();
    } catch (error) {
      await authUser.handle(error);
    }

    if (!authUser.isValid()) {
      return {
        status: false,
        errors: authUser.collectErrors().map((x) => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields(['username', 'email']);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error
        };
      }

      return {
        status: true,
        data: authUser
      };
    }
  }
}
