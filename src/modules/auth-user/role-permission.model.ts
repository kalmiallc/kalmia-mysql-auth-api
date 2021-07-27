import { integerParser, stringParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import { PoolConnection } from 'mysql2/promise';
import * as mysql from 'mysql2/promise';
import { BaseModel, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { DbTables, PermissionLevel } from '../../config/types';
import { prop } from '@rawmodel/core';
import { PermissionPass } from './decorators/permission.decorator';

export class RolePermission extends BaseModel {
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
        code: ValidatorErrorCode.ROLE_ID_NOT_PRESENT,
      },
    ],
  })
  public role_id: number;

  // /**
  //  * role
  //  */
  // @prop({
  //   parser: { resolver: Role },
  //   populatable: [
  //     PopulateFor.DB
  //   ],
  //   serializable: [
  //     SerializeFor.PROFILE,
  //     SerializeFor.ADMIN,
  //     SerializeFor.INSERT_DB,
  //     SerializeFor.UPDATE_DB
  //   ],
  // })
  // public role: Role;

  /**
   * permission
   */
  @prop({
    parser: { resolver: stringParser() },
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
        code: ValidatorErrorCode.PERMISSION_NOT_PRESENT,
      },
    ],
  })
  public permission: string;

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
        code: ValidatorErrorCode.READ_PERMISSION_LEVEL_NOT_SET,
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
        code: ValidatorErrorCode.WRITE_PERMISSION_LEVEL_NOT_SET,
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
        code: ValidatorErrorCode.EXECUTE_PERMISSION_LEVEL_NOT_SET,
      },
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: PermissionLevel.NONE
  })
  public execute: PermissionLevel;
  tableName: DbTables = DbTables.ROLE_PERMISSIONS;

  public constructor(data: any) {
    super(data);
  }

  public hasPermission(pass: PermissionPass) {
    return pass.permission === this.permission &&
      this[pass.type] &&
      (!pass.level || pass.level <= this[pass.type]);
  }

  // public: boolean {
  //   return !!this.role_id && !!this.permission;
  // }

  public async existsInDb(): Promise<boolean> {
    const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).paramQuery(
      `
      SELECT * FROM ${this.tableName}
      WHERE role_id = @role_id
        AND permission = @permission
    `,
      { role_id: this.role_id, permission: this.permission }
    );

    if (data && data.length) {
      return true;
    }
    return false;
  }
  // public async update(options?: { conn: PoolConnection }): Promise<any> {
  //   const serializedModel = this.serialize(SerializeFor.UPDATE_DB);
  //   let conn = null;

  //   if (options) {
  //     conn = options.conn || null;
  //   }

  //   // safeguard: remove fields we should not update
  //   delete serializedModel.role_id;
  //   delete serializedModel.permission;
  //   delete serializedModel.updateTime;
  //   delete serializedModel.updateUser;


  //   let isSingleTrans = false;
  //   if (!conn) {
  //     isSingleTrans = true;
  //     conn = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).start();
  //   }
  //   try {
  //     const createQuery = `
  //     UPDATE \`${this.tableName}\`
  //     SET
  //       ${Object.keys(serializedModel).map(x => `\`${x}\` = @${x}`).join(',\n')}
  //     WHERE role_id = @role_id
  //     AND permission = @permission
  //     `;

  //     // re-set id parameter for where clause.
  //     serializedModel.role_id = this.role_id;
  //     serializedModel.permission = this.permission;

  //     await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).paramExecute(createQuery, serializedModel, conn);

  //     if (isSingleTrans) {
  //       await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).commit(conn);
  //     }

  //   } catch (err) {
  //     if (isSingleTrans) {
  //       await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).rollback(conn);
  //     }
  //     throw new Error(err);
  //   }

  //   return this;
  // }
  // public async delete(conn?: PoolConnection): Promise<any> {
  //   let isSingleTrans = false;
  //   if (!conn) {
  //     isSingleTrans = true;
  //     conn = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).start();
  //   }
  //   try {

  //     await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).paramExecute(`
  //       DELETE FROM ${this.tableName}
  //       WHERE 
  //       role_id = @role_id
  //       AND permission = @permission
  //     `, {
  //       permission: this.permission,
  //       role_id: this.role_id
  //     }, conn);

  //     if (isSingleTrans) {
  //       await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).commit(conn);
  //     }

  //   } catch (err) {
  //     if (isSingleTrans) {
  //       await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as mysql.Pool).rollback(conn);
  //     }
  //     throw new Error(err);
  //   }
  // }


}
