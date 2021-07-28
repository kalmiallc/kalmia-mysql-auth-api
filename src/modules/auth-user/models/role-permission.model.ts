/* eslint-disable @typescript-eslint/member-ordering */
import { integerParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import * as mysql from 'mysql2/promise';
import { BaseModel, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { AuthDbTables, PermissionLevel, AuthValidatorErrorCode } from '../../../config/types';
import { prop } from '@rawmodel/core';
import { PermissionPass } from '../decorators/permission.decorator';

export class RolePermission extends BaseModel {
  tableName: AuthDbTables = AuthDbTables.ROLE_PERMISSIONS;
  /**
   * role_id
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
   * permission
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
   * read
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
   * write
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
   * execute
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

  public hasPermission(pass: PermissionPass) {
    return pass.permission === this.permission_id &&
      this[pass.type] &&
      (!pass.level || pass.level <= this[pass.type]);
  }

  // public: boolean {
  //   return !!this.role_id && !!this.permission_id;
  // }

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
