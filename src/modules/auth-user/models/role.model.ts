/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { integerParser, stringParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import {
  BaseModel,
  DbModelStatus,
  getQueryParams,
  MySqlUtil,
  PopulateFor,
  selectAndCountQuery,
  SerializeFor,
  uniqueFieldWithIdValidator
} from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { AuthDbTables, AuthValidatorErrorCode } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
import { RolePermission } from './role-permission.model';

/**
 * Role model.
 */
export class Role extends BaseModel {
  /**
   * Roles table.
   */
  tableName = AuthDbTables.ROLES;

  /**
   * Role's id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN]
  })
  public id: number;

  /**
   * Role's name property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_NAME_NOT_PRESENT
      },
      {
        resolver: uniqueFieldWithIdValidator(AuthDbTables.ROLES, 'name'),
        code: AuthValidatorErrorCode.ROLE_NAME_ALREADY_TAKEN
      }
    ]
  })
  public name: string;

  /**
   * Role's rolePermissions property definition.
   */
  @prop({
    parser: { resolver: RolePermission, array: true },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN],
    defaultValue: () => [],
    emptyValue: () => []
  })
  public rolePermissions: RolePermission[];

  /**
   * Checks whether a role has certain permissions
   * @param pass PermissionPass to check for. Role must meet or exceed permissions.
   * @returns boolean, whether role has permission.
   */
  public hasPermission(pass: PermissionPass): boolean {
    for (const rolePermission of this.rolePermissions) {
      if (rolePermission.hasPermission(pass)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Populates role's role permissions.
   *
   * @param conn (optional) database connection.
   * @returns Same instance with freshly populated role permissions.
   */
  public async populatePermissions(conn?: PoolConnection): Promise<this> {
    this.rolePermissions = [];
    const rows = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT 
        rp.*
      FROM ${AuthDbTables.ROLE_PERMISSIONS} rp
      WHERE rp.role_id = @roleId
      ORDER BY rp.role_id;
    `,
      { roleId: this.id },
      conn
    );

    for (const row of rows) {
      this.rolePermissions = [
        ...this.rolePermissions,
        new RolePermission({}).populate(
          {
            ...row,
            id: null
          },
          PopulateFor.DB
        )
      ];
    }

    return this;
  }

  /**
   * Populates role fields by name.
   *
   * @param name Role's name.
   */
  public async populateByName(name: string): Promise<this> {
    const res = await new MySqlUtil(await this.db()).paramExecute(
      `
        SELECT * FROM ${this.tableName}
        WHERE name = @name
      `,
      { name }
    );

    if (!res.length) {
      return this.reset();
    }
    this.populate(res[0]);
    await this.populatePermissions();
    return this;
  }

  /**
   * Populates role fields by id.
   *
   * @param id Role's id.
   */
  public async populateById(id: any, conn?: PoolConnection): Promise<this> {
    const res = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT * FROM ${this.tableName}
      WHERE id = @id
    `,
      { id },
      conn
    );

    if (!res.length) {
      return this.reset();
    }
    this.populate(res[0]);
    await this.populatePermissions(conn);
    return this;
  }

  /**
   * Deletes role permissions from the role.
   * @param permissionIds List of role permissions.
   */
  public async deleteRolePermissions(permissionIds: number[]) {
    try {
      await new MySqlUtil(await this.db()).paramExecute(
        `
          DELETE rp
          FROM ${AuthDbTables.ROLE_PERMISSIONS} rp
          WHERE rp.role_id = @id AND
            rp.permission_id IN (${permissionIds.join(', ')})
        `,
        {
          id: this.id
        }
      );
      this.rolePermissions = this.rolePermissions.filter((rp) => permissionIds.indexOf(rp.permission_id) === -1);
    } catch (error) {
      throw new Error(error);
    }
  }

  /**
   * Returns a list of roles based on the given filter.
   *
   * @param filter Object used for filtering.
   * @returns List of filtered roles.
   */
  public async getList(filter: any): Promise<{ items: Role[]; total: number }> {
    // Set default values or null for all params that we pass to sql query.
    const defaultParams = {
      id: null,
      search: null
    };

    // Map url query with sql fields.
    const fieldMap = {
      id: 'u.id'
    };

    const { params, filters } = getQueryParams(defaultParams, 'r', fieldMap, filter);
    const sqlQuery = {
      qSelect: `
        SELECT
          ${this.getSelectColumns('r')},
          r.name,
          rp.role_id,
          rp.permission_id,
          rp.read,
          rp.write,
          rp.execute,
          rp.name as rpName,
          rp.status as rpStatus,
          rp._createTime as rpCreateTime,
          rp._updateTime as rpUpdateTime,
          rp._createUser as rpCreateUser,
          rp._updateUser as rpUpdateUser
        `,
      qFrom: `
        FROM (SELECT * FROM \`${AuthDbTables.ROLES}\` LIMIT ${filters.limit} OFFSET ${filters.offset}) r
        LEFT JOIN \`${AuthDbTables.ROLE_PERMISSIONS}\` rp
          ON r.id = rp.role_id
        WHERE
          (@id IS NULL OR r.id = @id)
          AND (@search IS NULL
            OR r.name LIKE CONCAT('%', @search, '%')
          )
          AND (r.status < ${DbModelStatus.DELETED})
        `,
      qGroup: `
        GROUP BY
          ${this.getSelectColumns('r')},
          r.name,
          rp.name,
          rp.role_id,
          rp.permission_id,
          rp.read,
          rp.write,
          rp.execute,
          rp.status,
          rp._createTime,
          rp._updateTime,
          rp._createUser,
          rp._updateUser
        `,
      qFilter: `
        ORDER BY ${filters.orderStr};
      `
    };

    const res = await selectAndCountQuery(new MySqlUtil(await this.db()), sqlQuery, params, 'r.id');
    const rows = res.items;

    let roles: Role[] = [];
    for (const row of rows) {
      let role = roles.find((r) => r.id === row.id);
      if (!role) {
        role = new Role().populate(row, PopulateFor.DB);
        roles = [...roles, role];
      }

      const permission = new RolePermission({}).populate(
        {
          ...row,
          ...(row.rpName ? { name: row.rpName } : { name: null }),
          ...(row.rpStatus ? { status: row.rpStatus } : { status: null }),
          ...(row.rpCreateTime ? { _createTime: row.rpCreateTime } : { _createTime: null }),
          ...(row.rpUpdateTime ? { _updateTime: row.rpUpdateTime } : { _updateTime: null }),
          ...(row.rpCreateUser ? { _createUser: row.rpCreateUser } : { _createUser: null }),
          ...(row.rpUpdateUser ? { _updateUser: row.rpUpdateUser } : { _updateUser: null }),
          id: null
        },
        PopulateFor.DB
      );

      if (permission.exists()) {
        role.rolePermissions = [...role.rolePermissions, permission];
      }
    }

    return {
      items: roles,
      total: res.total
    };
  }

  /**
   * Hard deletes role, its role permissions and user roles from the database.
   * @param options Delete options.
   * @returns Deleted role (this).
   */
  public async delete(options: { conn?: PoolConnection } = {}) {
    const { singleTrans, sql, conn } = await this.getDbConnection(options.conn);

    try {
      const deleteUserRoles = `
        DELETE ur
        FROM ${AuthDbTables.USER_ROLES} ur
        JOIN ${AuthDbTables.ROLES} r
          ON ur.role_id = r.id
        WHERE r.id = @roleId
        `;
      await sql.paramExecute(deleteUserRoles, { roleId: this.id }, conn);

      const deleteRolePermissions = `
        DELETE rp
        FROM ${AuthDbTables.ROLE_PERMISSIONS} rp
        JOIN ${AuthDbTables.ROLES} r
          ON rp.role_id = r.id
        WHERE r.id = @roleId
      `;
      await sql.paramExecute(deleteRolePermissions, { roleId: this.id }, conn);

      const deleteRole = `
        DELETE FROM ${AuthDbTables.ROLES}
        WHERE id = @roleId
      `;
      await sql.paramExecute(deleteRole, { roleId: this.id }, conn);

      if (singleTrans) {
        await sql.commit(conn);
      }
    } catch (error) {
      if (singleTrans) {
        await sql.rollback(conn);
      }
      throw new Error(error);
    }

    return this;
  }
}
