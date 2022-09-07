/* eslint-disable @typescript-eslint/indent */
/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { integerParser, stringParser } from '@rawmodel/parsers';
import { isPresent } from '@rawmodel/utils';
import { emailValidator, presenceValidator, stringLengthValidator } from '@rawmodel/validators';
import * as bcrypt from 'bcryptjs';
import { BaseModel, DbModelStatus, MySqlUtil, PopulateFor, SerializeFor, uniqueFieldValidator, uniqueFieldWithIdValidator } from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { AuthDbTables, AuthValidatorErrorCode } from '../../../config/types';
import { PermissionPass } from '../../auth/interfaces/permission-pass.interface';
import { RolePermission } from './role-permission.model';
import { Role } from './role.model';

/**
 * Validates uniqueness of the ID field if model was not created yet.
 * @returns boolean
 */
const conditionalIdUniqueFieldValidator = () =>
  async function (this: AuthUser, value: any): Promise<boolean> {
    if (!isPresent(this._createTime)) {
      return uniqueFieldValidator(AuthDbTables.USERS, 'id')(value);
    }
    return true;
  };

/**
 * Generates random digit - used for PIN number generation.
 * @returns Random digit.
 */
function getRandomDigit() {
  return Math.floor(Math.random() * 10);
}

/**
 * Auth user model.
 */
export class AuthUser extends BaseModel {
  /**
   * Auth user table.
   */
  tableName = AuthDbTables.USERS;

  /**
   * Auth user's id property definition
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_ID_NOT_PRESENT
      },
      {
        resolver: conditionalIdUniqueFieldValidator(),
        code: AuthValidatorErrorCode.USER_ID_ALREADY_TAKEN
      }
    ],
    fakeValue: () => Math.floor(Math.random() * 10_000)
  })
  public id: number;

  /**
   * Auth user's status property definition
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    defaultValue: DbModelStatus.ACTIVE
  })
  public status: number;

  /**
   * Auth user's username property definition
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB, PopulateFor.ALL],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT
      },
      {
        resolver: (v?: any) => !emailValidator()(v),
        code: AuthValidatorErrorCode.USER_USERNAME_NOT_VALID
      },
      {
        resolver: uniqueFieldWithIdValidator(AuthDbTables.USERS, 'username'),
        code: AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN
      }
    ],
    fakeValue: () => `User${Math.floor(Math.random() * 10_000)}`
  })
  public username: string;

  /**
   * Auth user's email property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB, PopulateFor.ALL],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB],
    setter: (v) => (v ? v.toLowerCase().replace(' ', '') : v),
    validators: [
      {
        resolver: emailValidator(),
        code: AuthValidatorErrorCode.USER_EMAIL_NOT_VALID
      },
      {
        resolver: uniqueFieldWithIdValidator(AuthDbTables.USERS, 'email'),
        code: AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN
      }
    ],
    fakeValue: () => `${Math.floor(Math.random() * 10_000)}@domain-example.com`
  })
  public email: string;

  /**
   * Auth user's password hash property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    serializable: [SerializeFor.INSERT_DB],
    populatable: [PopulateFor.DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_PASSWORD_NOT_PRESENT
      }
    ],
    fakeValue: () => bcrypt.hashSync('Password123', bcrypt.genSaltSync(10))
  })
  public passwordHash: string;

  /**
   * Auth user's PIN property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    serializable: [SerializeFor.INSERT_DB],
    populatable: [PopulateFor.DB],
    validators: [
      {
        resolver: stringLengthValidator({ minOrEqual: 4, maxOrEqual: 4 }),
        code: AuthValidatorErrorCode.USER_PIN_NOT_CORRECT_LENGTH
      },
      {
        resolver: uniqueFieldWithIdValidator(AuthDbTables.USERS, 'PIN'),
        code: AuthValidatorErrorCode.USER_PIN_ALREADY_TAKEN
      }
    ],
    fakeValue: () => `${getRandomDigit()}${getRandomDigit()}${getRandomDigit()}${getRandomDigit()}`
  })
  public PIN: string;

  /**
   * Auth user's roles property definition.
   */
  @prop({
    parser: { resolver: Role, array: true },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL],
    validators: [],
    defaultValue: () => []
  })
  public roles: Role[];

  /**
   * Auth user's permissions property definition
   */
  @prop({
    parser: { resolver: RolePermission, array: true },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL],
    validators: [],
    defaultValue: () => []
  })
  public permissions: RolePermission[];

  /**
   * Tells if the provided password is valid.
   *
   * @param password User password.
   */
  public async comparePassword(password: string): Promise<boolean> {
    return typeof password === 'string' && password.length > 0 && (await bcrypt.compare(password, this.passwordHash));
  }

  /**
   * Sets user model's password hash. Does not update database entry on its own.
   *
   * @param password User password
   */
  public setPassword(password: string): void {
    const salt = bcrypt.genSaltSync(10);
    this.passwordHash = bcrypt.hashSync(password, salt);
  }

  /**
   * Populates model fields by email.
   *
   * @param email User's email.
   */
  public async populateByEmail(email: string, populateRoles: boolean = false) {
    email = email.toLowerCase().replace(/\s/g, '');
    const res = await new MySqlUtil(await this.db()).paramExecute(
      `
        SELECT * FROM ${this.tableName}
        WHERE email = @email
      `,
      { email }
    );

    if (!res.length) {
      return this.reset();
    }

    this.populate(res[0]);
    if (populateRoles) {
      await this.populateRoles();
    }

    return this;
  }

  /**
   * Populates model fields by username.
   *
   * @param username User's username.
   */
  public async populateByUsername(username: string, populateRoles: boolean = false) {
    const res = await new MySqlUtil(await this.db()).paramExecute(
      `
          SELECT * FROM ${this.tableName}
          WHERE username = @username
        `,
      { username }
    );

    if (!res.length) {
      return this.reset();
    }

    this.populate(res[0]);
    if (populateRoles) {
      await this.populateRoles();
    }

    return this;
  }

  /**
   * Populates model fields by PIN number.
   *
   * @param pin User's PIN number.
   */
  public async populateByPin(pin: string, populateRoles: boolean = false) {
    const res = await new MySqlUtil(await this.db()).paramExecute(
      `
            SELECT * FROM ${this.tableName}
            WHERE PIN = @pin
          `,
      { pin }
    );

    if (!res.length) {
      return this.reset();
    }

    this.populate(res[0]);
    if (populateRoles) {
      await this.populateRoles();
    }

    return this;
  }

  /**
   * Populates model fields by id.
   *
   * @param id User's id.
   */
  public async populateById(id: number, populateRoles: boolean = false): Promise<this> {
    await super.populateById(id);
    if (!this.id) {
      return this.reset();
    }

    if (populateRoles) {
      await this.populateRoles();
    }

    return this;
  }

  /**
   * Tells whether user has all the provided permissions.
   * @param permissionPasses Array of permission passed that are required of the user.
   * @returns boolean, whether user has all the permissions or not
   */
  public async hasPermissions(permissionPasses: PermissionPass[]): Promise<boolean> {
    if (!this.permissions || !this.permissions.length) {
      await this.populatePermissions();
    }

    for (const pass of permissionPasses) {
      let hasPermission = false;
      for (const perm of this.permissions) {
        if (perm.hasPermission(pass)) {
          hasPermission = true;
          break;
        }
      }
      if (!hasPermission) {
        return false;
      }
    }

    return true;
  }

  /**
   * Adds role to the user.
   *
   * @param roleId Role's id.
   */
  public async addRole(roleId: number, conn?: PoolConnection, populateRoles: boolean = true): Promise<AuthUser> {
    await new MySqlUtil(await this.db()).paramExecute(
      `
      INSERT IGNORE INTO ${AuthDbTables.USER_ROLES} (user_id, role_id)
      VALUES (@userId, @roleId)
    `,
      { userId: this.id, roleId },
      conn
    );

    if (populateRoles) {
      await this.populateRoles(conn);
    }
    return this;
  }

  /**
   * Returns true if user has provided role, false otherwise.
   * @param roleId id of the role in question
   * @param conn (optional) database connection
   */
  public async hasRole(roleId: number, conn?: PoolConnection): Promise<boolean> {
    if (!this.roles || !this.roles.length) {
      await this.populateRoles(conn);
    }

    for (const r of this.roles) {
      if (r.id === roleId) {
        return true;
      }
    }
    return false;
  }

  /**
   * Populates user's roles and their role permissions.
   * @param conn (optional) database connection
   * @returns the same instance of the object, but with the roles freshly populated.
   */
  public async populateRoles(conn?: PoolConnection): Promise<AuthUser> {
    this.roles = [];
    this.permissions = [];

    const rows = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT 
        r.*, 
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
      FROM ${AuthDbTables.ROLES} r
      JOIN ${AuthDbTables.USER_ROLES} ur
        ON ur.role_id = r.id
      LEFT JOIN ${AuthDbTables.ROLE_PERMISSIONS} rp
        ON rp.role_id = r.id
      WHERE ur.user_id = @userId
        AND r.status < ${DbModelStatus.DELETED}
      ORDER BY r.id;
    `,
      { userId: this.id },
      conn
    );

    for (const row of rows) {
      let role = this.roles.find((x) => x.id === row.id);
      if (!role) {
        role = new Role().populate(row, PopulateFor.DB);
        this.roles = [...this.roles, role];
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
        this.permissions = [...this.permissions, permission];
      }
    }

    return this;
  }

  /**
   * Populates user's permissions with their aggregated role permissions.
   * @param conn (optional) database connection
   * @returns same instance of user, but with permissions freshly populated
   */
  public async populatePermissions(conn?: PoolConnection): Promise<AuthUser> {
    this.permissions = [];
    const rows = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT
        rp.permission_id,
        IFNULL(MAX(rp.read), 0) \`read\`,
        IFNULL(MAX(rp.write), 0) \`write\`,
        IFNULL(MAX(rp.execute), 0) \`execute\`
      FROM ${AuthDbTables.USERS} u
      JOIN ${AuthDbTables.USER_ROLES} ur
        ON u.id = ur.user_id
      JOIN ${AuthDbTables.ROLES} r
        ON ur.role_id = r.id
          AND r.status < ${DbModelStatus.DELETED}
      JOIN ${AuthDbTables.ROLE_PERMISSIONS} rp
        ON ur.role_id = rp.role_id
      WHERE ur.user_id = @userId
      GROUP BY rp.permission_id;
    `,
      { userId: this.id },
      conn
    );

    for (const row of rows) {
      const permission = new RolePermission({}).populate(row, PopulateFor.DB);
      this.permissions = [...this.permissions, permission];
    }

    return this;
  }

  /**
   * Updates fields that are not updatable with the update method.
   * @param updateFields List of fields to update
   * @returns AuthUser (this)
   */
  public async updateNonUpdatableFields(updateFields: string[], connection?: PoolConnection): Promise<this> {
    const filtered = new Set(updateFields);
    filtered.delete('id');

    const updatable = {};
    for (const field of filtered) {
      if (this[field]) {
        updatable[field] = this[field];
      }
    }

    const { singleTrans, sql, conn } = await this.getDbConnection(connection);
    try {
      await sql.paramExecute(
        `
      UPDATE \`${this.tableName}\`
      SET
        ${Object.keys(updatable)
          .map((x) => `\`${x}\` = @${x}`)
          .join(',\n')}
      WHERE id = @id
      `,
        {
          ...updatable,
          id: this.id
        },
        conn
      );

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

  /**
   * Saves model data in the database as a new document.
   */
  public async create(options: { conn?: PoolConnection } = {}): Promise<this> {
    const serializedModel = this.serialize(SerializeFor.INSERT_DB);

    // remove non-creatable parameters
    delete serializedModel._createTime;
    delete serializedModel._updateTime;

    let isSingleTrans = false;
    let mySqlHelper: MySqlUtil;
    if (!options.conn) {
      isSingleTrans = true;
      const pool = await this.db();
      mySqlHelper = new MySqlUtil(pool);
    }

    if (isSingleTrans) {
      options.conn = await mySqlHelper.start();
    }
    mySqlHelper = new MySqlUtil();

    try {
      const createQuery = `
      INSERT INTO \`${this.tableName}\`
      ( ${Object.keys(serializedModel)
        .map((x) => `\`${x}\``)
        .join(', ')} )
      VALUES (
        ${Object.keys(serializedModel)
          .map((key) => `@${key}`)
          .join(', ')}
      )`;

      await mySqlHelper.paramExecute(createQuery, serializedModel, options.conn);
      if (!this.id) {
        const req = await mySqlHelper.paramExecute('SELECT last_insert_id() AS id;', null, options.conn);
        this.id = req[0].id;
      }

      if (isSingleTrans) {
        this._createTime = new Date();
        this._updateTime = this._createTime;
        await mySqlHelper.commit(options.conn);
      }
    } catch (error) {
      if (isSingleTrans) {
        await mySqlHelper.rollback(options.conn);
      }
      throw new Error(error);
    }

    return this;
  }

  /**
   * Revokes specified roles from user.
   * @param roleIds Role IDs.
   * @param conn (optional) Database connection.
   * @returns AuthUser (this)
   */
  public async revokeRoles(roleIds: number[], connection?: PoolConnection): Promise<this> {
    const { singleTrans, sql, conn } = await this.getDbConnection(connection);

    try {
      const deleteQuery = `
      DELETE ur
      FROM ${AuthDbTables.USER_ROLES} ur
      JOIN ${AuthDbTables.ROLES} r
        ON ur.role_id = r.id
      WHERE r.id IN (${roleIds.map((roleId) => `"${roleId}"`).join(', ')})
        AND ur.user_id = @userId
    `;

      await sql.paramExecute(
        deleteQuery,
        {
          userId: this.id
        },
        conn
      );

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
