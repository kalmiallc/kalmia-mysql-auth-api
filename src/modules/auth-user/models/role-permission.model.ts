/* eslint-disable @typescript-eslint/indent */
/* eslint-disable @typescript-eslint/member-ordering */
import { integerParser, stringParser } from '@rawmodel/parsers';
import { presenceValidator } from '@rawmodel/validators';
import { ActionOptions, BaseModel, DbModelStatus, enumInclusionValidator, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { AuthDbTables, PermissionLevel, AuthValidatorErrorCode } from '../../../config/types';
import { prop } from '@rawmodel/core';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
import { PoolConnection } from 'mysql2/promise';

/**
 * Role permission model.
 */
export class RolePermission extends BaseModel {
  /**
   * Role permissions table.
   */
  tableName: AuthDbTables = AuthDbTables.ROLE_PERMISSIONS;

  /**
   * Role permission's role_id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_ROLE_ID_NOT_PRESENT
      }
    ]
  })
  public role_id: number;

  /**
   * Role permission's permission_id property definition.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_PERMISSION_ID_NOT_PRESENT
      }
    ]
  })
  public permission_id: number;

  /**
   * Role permission's name property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_NAME_NOT_PRESENT
      }
    ]
  })
  public name: string;

  /**
   * Role permission's read property definition. Represents level of read access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN, PopulateFor.PROFILE],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_SET
      },
      {
        resolver: enumInclusionValidator(PermissionLevel),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_VALID
      }
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: () => PermissionLevel.NONE
  })
  public read: PermissionLevel;

  /**
   * Role permission's write property definition. Represents level of write access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN, PopulateFor.PROFILE],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_SET
      },
      {
        resolver: enumInclusionValidator(PermissionLevel),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID
      }
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: () => PermissionLevel.NONE
  })
  public write: PermissionLevel;

  /**
   * Role permission's execute property definition. Represents level of execute access.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB, PopulateFor.ADMIN, PopulateFor.PROFILE],
    serializable: [SerializeFor.PROFILE, SerializeFor.ADMIN, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET
      },
      {
        resolver: enumInclusionValidator(PermissionLevel),
        code: AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID
      }
    ],
    fakeValue: () => PermissionLevel.ALL,
    defaultValue: () => PermissionLevel.NONE
  })
  public execute: PermissionLevel;

  public constructor(data: any) {
    super(data);
  }

  /**
   * Tells if the model represents a document stored in the database.
   */
  public exists(): boolean {
    return !!this.role_id && !!this.permission_id && this.status !== DbModelStatus.DELETED;
  }

  /**
   * Tells whether a role permission meets or exceeds a certain permission requirement.
   * @param pass PermissionPass permission requirement.
   * @returns boolean, whether role permission has required permission
   */
  public hasPermission(pass: PermissionPass): boolean {
    return pass.permission === this.permission_id && this[pass.type] && (!pass.level || pass.level <= this[pass.type]);
  }

  /**
   * Checks whether a certain role permission exists in the db.
   * @returns Promise<boolean>
   */
  public async existsInDb(): Promise<boolean> {
    const data = await new MySqlUtil(await this.db()).paramExecute(
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

  /**
   * Populates model fields by Role ID and Permission ID.
   * @param roleId Role's ID.
   * @param permissionId Permission's ID.
   * @param conn (optional) Database connection.
   * @returns RolePermission (this)
   */
  public async populateByIds(roleId: number, permissionId: number, conn?: PoolConnection): Promise<this> {
    if (!roleId || !permissionId) {
      return this.reset();
    }

    const rows = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT * FROM ${this.tableName}
      WHERE role_id = @roleId
        AND permission_id = @permissionId
    `,
      { roleId, permissionId },
      conn
    );

    if (!rows?.length) {
      return this.reset();
    }

    this.populate(rows[0]);
    return this;
  }

  /**
   * Updates model fields.
   * @param options Update options.
   * @returns Updated role permission (this)
   */
  public async update(options: ActionOptions = {}): Promise<this> {
    if (!options?.context) {
      options.context = this.getContext();
    }

    if (options?.context?.user?.id) {
      this._updateUser = options.context.user.id;
    }

    const { singleTrans, sql, conn } = await this.getDbConnection(options.conn);
    const serializedModel = this.serialize(SerializeFor.UPDATE_DB);
    try {
      const updateQuery = `
      UPDATE \`${AuthDbTables.ROLE_PERMISSIONS}\`
      SET
        ${Object.keys(serializedModel)
          .map((x) => `\`${x}\` = @${x}`)
          .join(',\n')}
      WHERE role_id = @roleId
        AND permission_id = @permissionId
      `;

      await sql.paramExecute(
        updateQuery,
        {
          ...serializedModel,
          roleId: this.role_id,
          permissionId: this.permission_id
        },
        conn
      );

      this._updateTime = new Date();
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
