/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { integerParser, stringParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import { BaseModel, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { Pool, PoolConnection } from 'mysql2/promise';
import { AuthDbTables, AuthValidatorErrorCode } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
import { RolePermission } from './role-permission.model';

/**
 * Role model
 */
export class Role extends BaseModel {
  tableName: AuthDbTables = AuthDbTables.ROLES;

  /**
   * Role's id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN,
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
    ],
    validators: [],
  })
  public id: number;

  /**
   * Role's name property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN,
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB,
      SerializeFor.UPDATE_DB,
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_NAME_NOT_PRESENT,
      },
    ],
  })
  public name: string;

  /**
   * Role's rolePermissions property definition.
   */
  @prop({
    parser: { resolver: RolePermission, array: true },
    populatable: [
      PopulateFor.DB,
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN
    ],
    defaultValue: () => []
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
   * @param conn (optional) database connection
   * @returns same instance with freshly populated role permissions
   */
  public async getRolePermissions(conn?: PoolConnection): Promise<Role> {
    this.rolePermissions = [];
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

    for (const rp of res) {
      let rolePermission = this.rolePermissions.find(x => x.id === rp.id);
      if (!rolePermission) {
        rolePermission = new RolePermission({}).populate(rp, PopulateFor.DB);
        this.rolePermissions = [...this.rolePermissions, rolePermission];
      }
    }

    return this;
  }

  /**
   * Populates model fields by name.
   *
   * @param name Role's name.
   */
  public async populateByName(name: string) {
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
    await this.getRolePermissions();
    return this;
  }

  /**
   * Populates model fields by id.
   *
   * @param id Role's id.
   */
  public async populateById(id: any): Promise<any> {
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `
      SELECT * FROM ${this.tableName}
      WHERE id = @id
    `,
      { id }
    );

    if (!res.length) {
      return this.reset();
    }
    this.populate(res[0]);
    await this.getRolePermissions();
    return this;
  }

}
