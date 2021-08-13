import { DbModelStatus, MySqlConnManager, MySqlUtil, selectAndCountQuery } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthUser } from '../..';
import { env } from '../../config/env';
import { AuthAuthenticationErrorCode, AuthDbTables, AuthBadRequestErrorCode, AuthValidatorErrorCode, AuthJwtTokenType, AuthResourceNotFoundErrorCode, AuthSystemErrorCode } from '../../config/types';
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
   * Return array of auth users.
   * @param filter Pagination parameters. Can contain limit, offset and orderArr (array of properties to order by)
   * @param params Parameters to search by (id, search, status, role)
   * @returns list of auth user data objects.
   */
  async getAuthUsers(filter: any, params: any): Promise<IAuthResponse<any[]>> {
    const mysqlUtil = new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool);
    // set default values or null for all params that we pass to sql query
    const defaultParams = {
      id: null,
      search: null,
      status: null,
      role: null,
      isAdmin: null
    };

    for (const key of Object.keys(defaultParams)) {
      if (!params[key]) {
        params[key] = defaultParams[key];
      }
    }
    if (filter.limit === -1) {
      filter.limit = 500;
    }
    // params['isAdmin'] = overrideAdmin || this.getContext().hasUserRole(DefaultUserRoles.ADMIN) ? 1 : 0;

    // if (parseInt(urlQuery.search)) {
    //   params.id = parseInt(urlQuery.search);
    //   params.search = null;
    // }

    const sqlQuery = {
      qSelect: `
        SELECT
          u.id, u.username, u.email, u.status, u.PIN,
          GROUP_CONCAT(r.name) as userRoles,
          IF(CHAR_LENGTH(u.passwordHash) > 15, 'true', 'false') hasPW,
          u._createTime,
          u._updateTime
        `,
      qFrom: `
        FROM ${AuthDbTables.USERS} u
        LEFT JOIN ${AuthDbTables.USER_ROLES} ur
          ON ur.user_id = u.id
        LEFT JOIN ${AuthDbTables.ROLES} r
          ON r.id = ur.role_id
            AND r.status < ${DbModelStatus.DELETED}
        WHERE
          (@id IS NULL OR u.id = @id)
          AND (@role IS NULL OR FIND_IN_SET(ur.role_id, @role))
          AND (@search IS NULL
            OR u.email LIKE CONCAT('%', @search, '%')
            OR u.username LIKE CONCAT('%', @search, '%')
            OR CAST(u.id as CHAR) LIKE CONCAT('%', @search, '%')
          )
          AND (
            (@status IS NULL AND (u.status < ${DbModelStatus.DELETED} OR @id IS NOT NULL OR @isAdmin = 1))
            OR (@status IS NOT NULL AND FIND_IN_SET(u.status, @status))
          )
        `,
      qGroup: `
        GROUP BY
          u.id, u.username, u.email, u.status, u.pin, u._createTime, u._updateTime,
          hasPW
        `,
      qFilter: `
        ORDER BY ${`${(filter.orderArr || ['u.id']).join(', ') || null}`}
          LIMIT ${filter.limit || env.ITEMS_PER_PAGE || 10} OFFSET ${filter.offset || 0};
      `
    };
    try {
      const res = await selectAndCountQuery(mysqlUtil, sqlQuery, params, 'u.id');
      return {
        data: res,
        status: true,
      };
    } catch (error) {
      return {
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        status: false,
        details: error,
      };
    }
  }

  /**
   * Gets auth user by user id.
   * @param userId if of user to search by
   * @returns AuthUser with matching id
   */
  async getAuthUserById(userId: number): Promise<IAuthResponse<AuthUser>> {
    const user = await new AuthUser().populateById(userId);

    if (user.exists()) {
      return {
        status: true,
        data: user,
      };
    } else {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS],
      };
    }    
  }

  /**
   * Gets auth user by user email.
   * @param email if of user to search by
   * @returns AuthUser with matching email
   */
  async getAuthUserByEmail(email: string): Promise<IAuthResponse<AuthUser>> {
    const user = await new AuthUser().populateByEmail(email);

    if (user.exists()) {
      return {
        status: true,
        data: user,
      };
    } else {
      return {
        status: false,
        errors: [AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]
      };
    }    
  }

  /**
   * Grants roles to user. Roles must exist before being granted.
   * @param roles Array of role names to add to user.
   * @param userId Id of the user the roles should be granted to
   * @returns updated user roles
   */
  async grantRoles(roles: string[], userId: number): Promise<IAuthResponse<Role[]>> {
    if (!userId) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const user = await new AuthUser().populateById(userId);
    if (!user.id) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const queryGet = `
      SELECT id
      FROM ${AuthDbTables.ROLES}
      WHERE name IN (${roles.map((role) => `"${role}"`).join(', ')})
    `;
    const roleIds = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(queryGet);

    const roleAwaits = [];
    for (const role of roleIds) {
      roleAwaits.push(user.addRole(role.id));
    }
    await Promise.all(roleAwaits);
    await user.getRoles();
    
    return {
      status: true,
      data: user.roles,
    };
  }

  /**
   * Removes roles from user.
   * @param roles Array of role names to remove from user.
   * @param userId Id of the user the roles should be removed from
   * @returns updated user roles
   */
  async revokeRoles(roles: string[], userId: number): Promise<IAuthResponse<Role[]>> {
    if (!userId) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const user = await new AuthUser().populateById(userId);
    if (!user.id) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const query = `
      DELETE ur
      FROM ${AuthDbTables.USER_ROLES} ur
      JOIN ${AuthDbTables.ROLES} r
        ON ur.role_id = r.id
      WHERE r.name IN (${roles.map((role) => `"${role}"`).join(', ')})
        AND ur.user_id = @userId
    `;
    await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, { userId });
    await user.getRoles();
    
    return {
      status: true,
      data: user.roles,
    };
  }

  /**
   * Returns user's roles
   * @param userId id of user in question
   * @returns array of user roles
   */
  async getAuthUserRoles(userId: number): Promise<IAuthResponse<Role[]>> {
    if (!userId) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    const user = await new AuthUser().populateById(userId);
    if (!user.id) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    await user.getRoles();
    return {
      status: true,
      data: user.roles,
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

    await user.getPermissions();
    return {
      status: true,
      data: user.permissions,
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
    const tokenObj = new Token({
      payload: data,
      subject,
      user_id: userId
    });

    const token = await tokenObj.generate(exp);
    if (token) {
      return {
        status: true,
        data: token,
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
  async invalidateToken(token: string): Promise<IAuthResponse<boolean>> {
    if (!token) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const tokenObj = await new Token({}).populateByToken(token);
    const invalidation = await tokenObj.invalidateToken();
    if (invalidation) {
      return {
        status: true,
        data: invalidation,
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
  async validateToken(token: string, subject: string, userId: any = null): Promise<IAuthResponse<any>> {
    if (!token) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const tokenObj = new Token({ token, subject });
    const validation = await tokenObj.validateToken(userId);

    if (!validation) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.INVALID_TOKEN]
      };
    }

    return {
      status: true,
      data: validation,
    };
  }

  /**
   * Refreshes provided token if it is valid.
   * @param token token to be refreshed
   * @returns new, refreshed token
   */
  async refreshToken(token: string): Promise<IAuthResponse<string>> {
    if (!token) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }

    const tokenObj = new Token({ token });
    const refresh = await tokenObj.refresh();
    if (!refresh) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.INVALID_TOKEN]
      };
    }

    return {
      status: true,
      data: refresh,
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
        errors: role.collectErrors().map(x => x.code)
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
   * Adds role permissions to a role. A permission is only granted if role_id and permission_id combination doesn't already exist in database.
   * @param role name of the role permissions will be granted to.
   * @param permissions array of permissions to be granted.
   * @returns updated role permissions of the role
   */
  async addPermissionsToRole(role: string, permissions: INewPermission[]): Promise<IAuthResponse<RolePermission[]>> {
    try {
      const roleId = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `
        SELECT id
        FROM ${AuthDbTables.ROLES}
        WHERE name = @role
      `,
        { role }
      );

      if (!roleId.length) {
        return {
          status: false,
          errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
        };
      }

      for (const permission of permissions) {
        const rolePerm = new RolePermission({
          role_id: roleId[0].id,
        }).populate(permission);

        if (!await rolePerm.existsInDb()) {
          await rolePerm.create();
        }
      }
    } catch (error) {
      return {
        status: false,
        errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
        details: error,
      };
    }
  
    const roleObj = await new Role().populateByName(role);
    return {
      status: true,
      data: roleObj.rolePermissions,
    };
  }

  /**
   * Removes role permissions from a role.
   * @param role Name of the role permissions should be removed from.
   * @param permissions ids of permissions to be removed from the role.
   * @returns updated role permissions
   */
  async removePermissionsFromRole(role: string, permissions: number[]): Promise<IAuthResponse<RolePermission[]>> {
    try {
      const roleId = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `
        SELECT id
        FROM ${AuthDbTables.ROLES}
        WHERE name = @role
      `,
        { role }
      );

      if (!roleId.length) {
        return {
          status: false,
          errors: [AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]
        };
      }

      const query = `
          DELETE rp
          FROM ${AuthDbTables.ROLE_PERMISSIONS} rp
          WHERE rp.role_id = @roleId AND
            rp.permission_id IN (${permissions.join(', ')})
        `;

      const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, {
        roleId: roleId[0].id
      });

      const roleObj = await new Role().populateByName(role);
      return {
        status: true,
        data: roleObj.rolePermissions,
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
   * Return role's role permissions
   * @param role name of the role to get permissions of
   * @returns role's role permissions
   */
  async getRolePermissions(role: string): Promise<IAuthResponse<RolePermission[]>> {
    const roleObj = await new Role().populateByName(role);
    return {
      status: true,
      data: roleObj.rolePermissions,
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
      return await this.generateToken({ id: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
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
      return await this.generateToken({ id: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
    } else {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
  }

  /**
   * Validates user's login credentials. If accepted, returns authentication JWT.
   * @param pin User's PIN number.
   * @returns Authentication JWT
   */
  async loginPin(pin: string): Promise<IAuthResponse<string>> {
    const user: AuthUser = await new AuthUser({}).populateByPin(pin);
  
    if (!user.exists()) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
  
    return await this.generateToken({ id: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
  }



  /**
   * Creates auth user with provided data
   * @param data auth user data
   * @returns new auth user
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
          details: error,
        };
      }

      return {
        status: true,
        data: user
      };
    } else {
      return {
        status: false,
        errors: user.collectErrors().map(x => x.code)
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
        details: error,
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

    if (force || await authUser.comparePassword(password)) {
      authUser.setPassword(newPassword);
      try {
        await authUser.validate();
      } catch (error) {
        await authUser.handle(error);
      }

      if (!authUser.isValid()) {
        return {
          status: false,
          errors: authUser.collectErrors().map(x => x.code)
        };
      } else {
        try {
          await authUser.updateNonUpdatableFields(['passwordHash']);
        } catch (error) {
          return {
            status: false,
            errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
            details: error,
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
        errors: authUser.collectErrors().map(x => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields(['email']);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error,
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
        errors: authUser.collectErrors().map(x => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields(['username']);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error,
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
   * @param data User's data.
   * @returns Updated auth user.
   */
  async update(userId: any, data: any): Promise<IAuthResponse<AuthUser>> {
    if (data?.password) {
      delete data.password;
    }

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
        errors: authUser.collectErrors().map(x => x.code)
      };
    } else {
      try {
        await authUser.updateNonUpdatableFields([
          'username',
          'email',
        ]);
      } catch (error) {
        return {
          status: false,
          errors: [AuthSystemErrorCode.SQL_SYSTEM_ERROR],
          details: error,
        };
      }

      return {
        status: true,
        data: authUser
      };
    }
  }

}
