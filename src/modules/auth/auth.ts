import { DbModelStatus, MySqlConnManager, MySqlUtil, selectAndCountQuery } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthUser } from '../..';
import { env } from '../../config/env';
import { AuthAuthenticationErrorCode, AuthDbTables, AuthBadRequestErrorCode, AuthValidatorErrorCode, AuthJwtTokenType } from '../../config/types';
import { PermissionPass } from '../auth-user/decorators/permission.decorator';
import { IAuthUser } from '../auth-user/interfaces/auth-user.interface';
import { RolePermission } from '../auth-user/models/role-permission.model';
import { Role } from '../auth-user/models/role.model';
import { Token } from '../token/token.model';
import { IAuthResponse } from './interfaces/auth-response.interface';
import { IAuth } from './interfaces/auth.interface';
import { INewPermission } from './interfaces/new-permission.interface';

export class Auth implements IAuth {
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
   * Return array of auth users
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
          u._createdAt,
          u._updatedAt,
          u._deletedAt
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
          u.id, u.username, u.email, u.status, u.pin, u._createdAt, u._updatedAt, u._deletedAt,
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
    } catch (e) {
      return {
        errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR],
        status: false,
      };
    }
  }

  /**
   * Gets auth user by user id.
   * @param id if of user to search by
   * @returns AuthUser with matching id
   */
  async getAuthUserById(id: number): Promise<IAuthResponse<AuthUser>> {
    
    const user: AuthUser = new AuthUser();
    await user.populateById(id);
    return {
      status: true,
      data: user,
    };
  }

  /**
   * Gets auth user by user email.
   * @param email if of user to search by
   * @returns AuthUser with matching email
   */
  async getAuthUserByEmail(email: string): Promise<IAuthResponse<AuthUser>> {
    
    const user: AuthUser = new AuthUser({});
    await user.populateByEmail(email);
    return {
      status: true,
      data: user,
    };
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
    const user: AuthUser = await new AuthUser().populateById(userId);
    
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

    const user: AuthUser = await new AuthUser().populateById(userId);
    
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
    const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, { userId });

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

    const user: AuthUser = await new AuthUser().populateById(userId);
    
    if (!user.id) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
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

    const user: AuthUser = await new AuthUser().populateById(userId);
    
    if (!user.id) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
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
   * Ivalidates the provided token in the database.
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
      errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
    };
  }

  /**
   * Validates token. If valid, returns token payload.
   * @param token token to be validated
   * @param subject JWT subject for token to be validated with
   * @returns token payload
   */
  async validateToken(token: string, subject: string): Promise<IAuthResponse<any>> {
    if (!token) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.MISSING_DATA_ERROR]
      };
    }
    const tokenObj = new Token({ token, subject });
    const validation = await tokenObj.validateToken();
    if (!validation) {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.INVALID_AUTHENTICATION_TOKEN]
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
        errors: [AuthAuthenticationErrorCode.INVALID_AUTHENTICATION_TOKEN]
      };
    }
    return {
      status: true,
      data: refresh,
    };
  }

  /**
   * Creates a new role, provided one with the same name doesn't already exist
   * @param name Name of the new role
   * @returns Role object of the new role
   */
  async createRole(name: string): Promise<IAuthResponse<Role>> {
    const role = await new Role({ name });
    try {
      await role.validate();
    } catch (e) {
      return {
        status: false,
        errors: [AuthValidatorErrorCode.ROLE_NAME_NOT_PRESENT]
      };
    }
    try {
      await role.create();
      return {
        status: true,
        data: role
      };
    } catch (e) {
    }
    return {
      status: false,
      errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
    };

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
    } catch (e) {
      await new MySqlUtil(conn).rollback(conn);
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
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
          errors: [AuthValidatorErrorCode.ROLE_ID_NOT_PRESENT]
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
    } catch (e) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
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
          errors: [AuthValidatorErrorCode.ROLE_ID_NOT_PRESENT]
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
    } catch (e) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
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
   * @param email user's email
   * @param pwd user's password
   * @returns Authentication JWT
   */
  async loginEmail(email: string, pwd: string): Promise<IAuthResponse<string>> {
    const user: AuthUser = await new AuthUser({}).populateByEmail(email);

    if (!user.isPersistent()) {
      // throw new UnauthenticatedError(AuthenticationErrorCode.USER_NOT_AUTHENTICATED, 'auth-mysql/loginEmail');
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }

    if (await user.comparePassword(pwd)) {
      return await this.generateToken({ id: user.id }, AuthJwtTokenType.USER_AUTHENTICATION);
    } else {
      return {
        status: false,
        errors: [AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]
      };
    }
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
    } catch (err) {
      await user.handle(err);
    }

    if (user.isValid()) {
      await user.create();
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
   * Updates existing auth user.
   * @param data Updated user data. Should contain id for identification.
   * @returns Updated user.
   */
  async updateAuthUser(data: IAuthUser): Promise<IAuthResponse<AuthUser>> {
    const user: AuthUser = await new AuthUser().populateById(data.id);
    user.populate(data);

    try {
      await user.validate();
    } catch (err) {
      await user.handle(err);
    }

    if (user.isValid()) {
      if ((data as any).password) {
        user.setPassword((data as any).password);
      }
      await user.update();
      
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
      const user: AuthUser = await new AuthUser().populateById(userId);
      await user.delete();
      
      return {
        status: true,
        data: user
      };
    } catch (e) {
      return {
        status: false,
        errors: [AuthBadRequestErrorCode.DEFAULT_SQL_ERROR]
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

}
