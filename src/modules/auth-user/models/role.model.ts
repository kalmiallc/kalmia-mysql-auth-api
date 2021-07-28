/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { integerParser, stringParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import { BaseModel, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { Pool, PoolConnection } from 'mysql2/promise';
import { AuthDbTables, AuthValidatorErrorCode } from '../../../config/types';
import { PermissionPass } from '../decorators/permission.decorator';
import { RolePermission } from './role-permission.model';

export class Role extends BaseModel {
  tableName: AuthDbTables = AuthDbTables.ROLES;
  /**
   * id
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
   * name
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
   * rolePermissions
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

  public hasPermission(pass: PermissionPass) {
    for (const rolePermission of this.rolePermissions) {
      if (rolePermission.hasPermission(pass)) {
        return true;
      }
    }
    return false;
  }

  public async getRolePermissions(conn?: PoolConnection) {
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
        this.rolePermissions.push(rolePermission);
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
