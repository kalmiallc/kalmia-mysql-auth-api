/* eslint-disable @typescript-eslint/member-ordering */
import { integerParser, stringParser } from '@rawmodel/parsers';
import { emailValidator, presenceValidator } from '@rawmodel/validators';
import * as bcrypt from 'bcryptjs';
import { PoolConnection, Pool } from 'mysql2/promise';
import { Role } from './role.model';
import { RolePermission } from './role-permission.model';
import { BaseModel, DbModelStatus, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor, uniqueFieldValue } from 'kalmia-sql-lib';
import { AuthDbTables, AuthValidatorErrorCode } from '../../../config/types';
import { prop } from '@rawmodel/core';
import { PermissionPass } from '../decorators/permission.decorator';

/**
 * User model.
 */
export class AuthUser extends BaseModel {

  tableName = AuthDbTables.USERS;
  /**
   * id
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [SerializeFor.INSERT_DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_ID_NOT_PRESENT
      },
    ],
    handlers: [
      {
        resolver: uniqueFieldValue('user', 'id'),
        code: AuthValidatorErrorCode.USER_ID_ALREADY_TAKEN
      }
    ],
    fakeValue() {
      return Math.floor(Math.random() * 10_000);
    }
  })
  public id: number;

  /**
   * id
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    serializable: [SerializeFor.PROFILE],
    defaultValue: DbModelStatus.ACTIVE
  })
  public status: number;

  /**
   * id
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [SerializeFor.INSERT_DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB, SerializeFor.UPDATE_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT
      },
      {
        resolver: (v?: any) => !emailValidator()(v),
        code: AuthValidatorErrorCode.USER_USERNAME_NOT_VALID
      }
    ],
    handlers: [
      {
        resolver: uniqueFieldValue('user', 'username'),
        code: AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN
      }
    ],
  })
  public username: string;

  /**
   * User's collection.
   */
  collectionName: AuthDbTables = AuthDbTables.USERS;

  /**
   * User's email property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
    setter(v) {
      return v ? v.toLowerCase().replace(' ', '') : v;
    },
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_EMAIL_NOT_PRESENT
      },
      {
        resolver: emailValidator(),
        code: AuthValidatorErrorCode.USER_EMAIL_NOT_VALID
      }
    ],
    handlers: [
      {
        resolver: uniqueFieldValue('user', 'email'),
        code: AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN
      }
    ],
    fakeValue() {
      return `${Math.floor(Math.random() * 10_000)}@domain-example.com`;
    }
  })
  public email: string;

  /**
   * User's password hash property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    serializable: [SerializeFor.INSERT_DB],
    validators: [
      {
        resolver: presenceValidator(),
        code: AuthValidatorErrorCode.USER_PASSWORD_NOT_PRESENT
      }
    ],
    fakeValue: bcrypt.hashSync('Password123', bcrypt.genSaltSync(10)),
    defaultValue: bcrypt.genSaltSync(10)
  })
  public passwordHash: string;

  /**
   * User's PIN property definition.
   */
  @prop({
    parser: { resolver: stringParser() },
    serializable: [SerializeFor.INSERT_DB],
    validators: [],
    fakeValue: bcrypt.hashSync('Password123', bcrypt.genSaltSync(10)),
    defaultValue: bcrypt.genSaltSync(10)
  })
  public PIN: string;

  
  /**
   * user role
   */
  @prop({
    parser: { resolver: Role, array: true },
    populatable: [
      PopulateFor.DB,
      PopulateFor.PROFILE
    ],
    serializable: [
      SerializeFor.PROFILE
    ],
    validators: [],
  })
  public roles: Role[];

  
  /**
   * user role
   */
  @prop({
    parser: { resolver: RolePermission, array: true },
    populatable: [
      PopulateFor.DB,
      PopulateFor.PROFILE
    ],
    serializable: [
      SerializeFor.PROFILE
    ],
    validators: [],
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

  public setPassword(password: string) {
    const salt = bcrypt.genSaltSync(10);
    this.passwordHash = bcrypt.hashSync(password, salt);
  }

  

  /**
   * Populates model fields by email.
   *
   * @param email User's email.
   */
  public async populateByEmail(email: string) {
    email = email.toLowerCase().replace(/\s/g, '');
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
      `
        SELECT * FROM ${this.collectionName}
        WHERE email = @email
      `,
      { email }
    );

    if (!res.length) {
      return this.reset();
    }
    this.populate(res[0]);
    await this.getRoles();
    await this.getPermissions();
    return this;
  }

  public async populateById(id: number): Promise<this> {
    await super.populateById(id);
    if (!this.id) {
      return this.reset();
    }
    await this.getRoles();
    await this.getPermissions();
    return this;
  }

  public async markDeleted(): Promise<boolean> {
    if (!this.id) {
      return false;
    }
    const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `
      UPDATE \`${AuthDbTables.USERS}\`
      SET status = @status
      WHERE id = @id
    `,
      { id: this.id, status: DbModelStatus.DELETED }
    );
    return true;
  }

  public async hasPermissions(permissionPasses: PermissionPass[]): Promise<boolean> {
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
  public async addRole(roleId: number, conn?: PoolConnection) {
    await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
      `
      INSERT IGNORE INTO ${AuthDbTables.USER_ROLES} (user_id, role_id)
      VALUES (@userId, @roleId)
    `,
      { userId: this.id, roleId },
      conn
    );

    return await this.getRoles(conn);
  }

  public async hasRole(roleId: number, conn?: PoolConnection) {
    if (!this.roles || !this.roles.length) {
      await this.getRoles(conn);
    }
    for (const r of this.roles) {
      if (r.id === roleId) {
        return true;
      }
    }
    return false;
  }

  public async getRoles(conn?: PoolConnection) {
    this.roles = [];
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
      `
      SELECT 
        r.*, 
        rp.*
      FROM ${AuthDbTables.ROLES} r
      JOIN ${AuthDbTables.USER_ROLES} ur
      ON ur.role_id = r.id
      JOIN ${AuthDbTables.ROLE_PERMISSIONS} rp
      ON rp.role_id = r.id
      WHERE ur.user_id = @userId
        AND r.status < \`${DbModelStatus.DELETED}\`
      ORDER BY r.id;
    `,
      { userId: this.id },
      conn
    );

    for (const r of res) {
      let role = this.roles.find(x => x.id === r.id);
      if (!role) {
        role = new Role().populate(r, PopulateFor.DB);
        this.roles.push(role);
      }
      let permission = role.rolePermissions.find(x => x.permission_id == r.permission_id);
      if (!permission) {
        permission = new RolePermission({}).populate(r, PopulateFor.DB);
        role.rolePermissions = [...role.rolePermissions, permission];
      }
    }

    return this;
  }
  public async getPermissions(conn?: PoolConnection) {
    this.permissions = [];
    const res = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
          AND ur.status < \`${DbModelStatus.DELETED}\`
      JOIN ${AuthDbTables.ROLE_PERMISSIONS} rp
        ON ur.role_id = rp.role_id
      WHERE ur.user_id = @userId
      GROUP BY rp.permission_id;
    `,
      { userId: this.id },
      conn
    );

    for (const p of res) {
      let permission = this.permissions.find(x => x.id === p.id);
      if (!permission) {
        permission = new RolePermission({}).populate(p, PopulateFor.DB);
        this.permissions.push(permission);
      }
    }

    return this;
  }
}
