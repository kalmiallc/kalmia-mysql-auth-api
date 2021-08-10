/* eslint-disable @typescript-eslint/member-ordering */
import { integerParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import * as mysql from 'mysql2/promise';
import { BaseModel, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { AuthDbTables, PermissionLevel, AuthValidatorErrorCode } from '../../../config/types';
import { prop } from '@rawmodel/core';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';

/**
 * Role permission model
 */
export class RolePermission extends BaseModel {
  tableName: AuthDbTables = AuthDbTables.ROLE_PERMISSIONS;

  /**
   * Role permission's role_id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_ID_NOT_PRESENT,
      },
    ],
  })
  public role_id: number;

  /**
   * Role permission's permission_id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.PERMISSION_NOT_PRESENT,
      },
    ],
  })
  public permission_id: number;

  /**
   * Role permission's read property definition. Represents level of read access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB,
      SerializeFor.UPDATE_DB
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.READ_PERMISSION_LEVEL_NOT_SET,
      },
    ],
    fakeValue() {
      return PermissionLevel.ALL; 
    },
    defaultValue: PermissionLevel.NONE
  })
  public read: PermissionLevel;

  /**
   * Role permission's write property definition. Represents level of write access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB,
      SerializeFor.UPDATE_DB
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.WRITE_PERMISSION_LEVEL_NOT_SET,
      },
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: PermissionLevel.NONE
  })
  public write: PermissionLevel;

  /**
   * Role permission's execute property definition. Represents level of execute access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [
      PopulateFor.DB,
      PopulateFor.ADMIN
    ],
    serializable: [
      SerializeFor.PROFILE,
      SerializeFor.ADMIN,
      SerializeFor.INSERT_DB,
      SerializeFor.UPDATE_DB
    ],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.EXECUTE_PERMISSION_LEVEL_NOT_SET,
      },
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: PermissionLevel.NONE
  })
  public execute: PermissionLevel;

  public constructor(data: any) {
    super(data);
  }

  /**
   * Tells whether a role permission meets or exceeds a certain permission requirement.
   * @param pass PermissionPass permission requirement.
   * @returns boolean, whether role permission has required permission
   */
  public hasPermission(pass: PermissionPass): boolean {
    return pass.permission === this.permission_id &&
      this[pass.type] &&
      (!pass.level || pass.level <= this[pass.type]);
  }

  /**
   * Checks whether a certain role permission exists in the db.
   * @returns Promise<boolean>
   */
  public async existsInDb(): Promise<boolean> {
    const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).paramQuery(
      `
      SELECT * FROM ${this.tableName}
      WHERE role_id = @role_id
        AND permission_id = @permission_id
    `,
      { role_id: this.role_id, permission_id: this.permission_id }
    );

    if (data && data.length) {
      return true;
    }
    return false;
  }

}
