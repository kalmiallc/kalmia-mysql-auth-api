"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthUser = void 0;
/* eslint-disable @typescript-eslint/indent */
/* eslint-disable @typescript-eslint/member-ordering */
const core_1 = require("@rawmodel/core");
const parsers_1 = require("@rawmodel/parsers");
const validators_1 = require("@rawmodel/validators");
const bcrypt = require("bcryptjs");
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../../config/types");
const role_permission_model_1 = require("./role-permission.model");
const role_model_1 = require("./role.model");
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
class AuthUser extends kalmia_sql_lib_1.BaseModel {
    constructor() {
        super(...arguments);
        /**
         * Auth user table.
         */
        this.tableName = types_1.AuthDbTables.USERS;
    }
    /**
     * Tells if the provided password is valid.
     *
     * @param password User password.
     */
    async comparePassword(password) {
        return typeof password === 'string' && password.length > 0 && (await bcrypt.compare(password, this.passwordHash));
    }
    /**
     * Sets user model's password hash. Does not update database entry on its own.
     *
     * @param password User password
     */
    setPassword(password) {
        const salt = bcrypt.genSaltSync(10);
        this.passwordHash = bcrypt.hashSync(password, salt);
    }
    /**
     * Populates model fields by email.
     *
     * @param email User's email.
     */
    async populateByEmail(email, populateRoles = false) {
        email = email.toLowerCase().replace(/\s/g, '');
        const res = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
        SELECT * FROM ${this.tableName}
        WHERE email = @email
      `, { email });
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
    async populateByUsername(username, populateRoles = false) {
        const res = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
          SELECT * FROM ${this.tableName}
          WHERE username = @username
        `, { username });
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
    async populateByPin(pin, populateRoles = false) {
        const res = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
            SELECT * FROM ${this.tableName}
            WHERE PIN = @pin
          `, { pin });
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
    async populateById(id, populateRoles = false) {
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
    async hasPermissions(permissionPasses) {
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
    async addRole(roleId, conn, populateRoles = true) {
        await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      INSERT IGNORE INTO ${types_1.AuthDbTables.USER_ROLES} (user_id, role_id)
      VALUES (@userId, @roleId)
    `, { userId: this.id, roleId }, conn);
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
    async hasRole(roleId, conn) {
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
    async populateRoles(conn) {
        this.roles = [];
        this.permissions = [];
        const rows = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
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
      FROM ${types_1.AuthDbTables.ROLES} r
      JOIN ${types_1.AuthDbTables.USER_ROLES} ur
        ON ur.role_id = r.id
      LEFT JOIN ${types_1.AuthDbTables.ROLE_PERMISSIONS} rp
        ON rp.role_id = r.id
      WHERE ur.user_id = @userId
        AND r.status < ${kalmia_sql_lib_1.DbModelStatus.DELETED}
      ORDER BY r.id;
    `, { userId: this.id }, conn);
        for (const row of rows) {
            let role = this.roles.find((x) => x.id === row.id);
            if (!role) {
                role = new role_model_1.Role().populate(row, kalmia_sql_lib_1.PopulateFor.DB);
                this.roles = [...this.roles, role];
            }
            const permission = new role_permission_model_1.RolePermission({}).populate(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({}, row), (row.rpName ? { name: row.rpName } : { name: null })), (row.rpStatus ? { status: row.rpStatus } : { status: null })), (row.rpCreateTime ? { _createTime: row.rpCreateTime } : { _createTime: null })), (row.rpUpdateTime ? { _updateTime: row.rpUpdateTime } : { _updateTime: null })), (row.rpCreateUser ? { _createUser: row.rpCreateUser } : { _createUser: null })), (row.rpUpdateUser ? { _updateUser: row.rpUpdateUser } : { _updateUser: null })), { id: null }), kalmia_sql_lib_1.PopulateFor.DB);
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
    async populatePermissions(conn) {
        this.permissions = [];
        const rows = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT
        rp.permission_id,
        IFNULL(MAX(rp.read), 0) \`read\`,
        IFNULL(MAX(rp.write), 0) \`write\`,
        IFNULL(MAX(rp.execute), 0) \`execute\`
      FROM ${types_1.AuthDbTables.USERS} u
      JOIN ${types_1.AuthDbTables.USER_ROLES} ur
        ON u.id = ur.user_id
      JOIN ${types_1.AuthDbTables.ROLES} r
        ON ur.role_id = r.id
          AND r.status < ${kalmia_sql_lib_1.DbModelStatus.DELETED}
      JOIN ${types_1.AuthDbTables.ROLE_PERMISSIONS} rp
        ON ur.role_id = rp.role_id
      WHERE ur.user_id = @userId
      GROUP BY rp.permission_id;
    `, { userId: this.id }, conn);
        for (const row of rows) {
            const permission = new role_permission_model_1.RolePermission({}).populate(row, kalmia_sql_lib_1.PopulateFor.DB);
            this.permissions = [...this.permissions, permission];
        }
        return this;
    }
    /**
     * Updates fields that are not updatable with the update method.
     * @param updateFields List of fields to update
     * @returns AuthUser (this)
     */
    async updateNonUpdatableFields(updateFields, connection) {
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
            await sql.paramExecute(`
      UPDATE \`${this.tableName}\`
      SET
        ${Object.keys(updatable)
                .map((x) => `\`${x}\` = @${x}`)
                .join(',\n')}
      WHERE id = @id
      `, Object.assign(Object.assign({}, updatable), { id: this.id }), conn);
            if (singleTrans) {
                await sql.commit(conn);
            }
        }
        catch (error) {
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
    async create(options = {}) {
        const serializedModel = this.serialize(kalmia_sql_lib_1.SerializeFor.INSERT_DB);
        // remove non-creatable parameters
        delete serializedModel._createTime;
        delete serializedModel._updateTime;
        let isSingleTrans = false;
        let mySqlHelper;
        if (!options.conn) {
            isSingleTrans = true;
            const pool = await this.db();
            mySqlHelper = new kalmia_sql_lib_1.MySqlUtil(pool);
        }
        if (isSingleTrans) {
            options.conn = await mySqlHelper.start();
        }
        mySqlHelper = new kalmia_sql_lib_1.MySqlUtil();
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
        }
        catch (error) {
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
    async revokeRoles(roleIds, connection) {
        const { singleTrans, sql, conn } = await this.getDbConnection(connection);
        try {
            const deleteQuery = `
      DELETE ur
      FROM ${types_1.AuthDbTables.USER_ROLES} ur
      JOIN ${types_1.AuthDbTables.ROLES} r
        ON ur.role_id = r.id
      WHERE r.id IN (${roleIds.map((roleId) => `"${roleId}"`).join(', ')})
        AND ur.user_id = @userId
    `;
            await sql.paramExecute(deleteQuery, {
                userId: this.id
            }, conn);
            if (singleTrans) {
                await sql.commit(conn);
            }
        }
        catch (error) {
            if (singleTrans) {
                await sql.rollback(conn);
            }
            throw new Error(error);
        }
        return this;
    }
}
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.INSERT_DB, kalmia_sql_lib_1.SerializeFor.UPDATE_DB],
        defaultValue: () => kalmia_sql_lib_1.DbModelStatus.ACTIVE,
        emptyValue: () => kalmia_sql_lib_1.DbModelStatus.INACTIVE
    }),
    __metadata("design:type", Number)
], AuthUser.prototype, "status", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ALL],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT
            },
            {
                resolver: (0, kalmia_sql_lib_1.uniqueFieldWithIdValidator)(types_1.AuthDbTables.USERS, 'username'),
                code: types_1.AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN
            }
        ],
        fakeValue: () => `User${Math.floor(Math.random() * 10000)}`
    }),
    __metadata("design:type", String)
], AuthUser.prototype, "username", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ALL],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        setter: (v) => (v ? v.toLowerCase().replace(' ', '') : v),
        validators: [
            {
                resolver: (0, validators_1.emailValidator)(),
                code: types_1.AuthValidatorErrorCode.USER_EMAIL_NOT_VALID
            },
            {
                resolver: (0, kalmia_sql_lib_1.uniqueFieldWithIdValidator)(types_1.AuthDbTables.USERS, 'email'),
                code: types_1.AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN
            }
        ],
        fakeValue: () => `${Math.floor(Math.random() * 10000)}@domain-example.com`
    }),
    __metadata("design:type", String)
], AuthUser.prototype, "email", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        serializable: [kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.USER_PASSWORD_NOT_PRESENT
            }
        ],
        fakeValue: () => bcrypt.hashSync('Password123', bcrypt.genSaltSync(10))
    }),
    __metadata("design:type", String)
], AuthUser.prototype, "passwordHash", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        serializable: [kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        validators: [
            {
                resolver: (0, validators_1.stringLengthValidator)({ minOrEqual: 4, maxOrEqual: 4 }),
                code: types_1.AuthValidatorErrorCode.USER_PIN_NOT_CORRECT_LENGTH
            },
            {
                resolver: (0, kalmia_sql_lib_1.uniqueFieldWithIdValidator)(types_1.AuthDbTables.USERS, 'PIN'),
                code: types_1.AuthValidatorErrorCode.USER_PIN_ALREADY_TAKEN
            }
        ],
        fakeValue: () => `${getRandomDigit()}${getRandomDigit()}${getRandomDigit()}${getRandomDigit()}`
    }),
    __metadata("design:type", String)
], AuthUser.prototype, "PIN", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: role_model_1.Role, array: true },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL],
        validators: [],
        defaultValue: () => []
    }),
    __metadata("design:type", Array)
], AuthUser.prototype, "roles", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: role_permission_model_1.RolePermission, array: true },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL],
        validators: [],
        defaultValue: () => []
    }),
    __metadata("design:type", Array)
], AuthUser.prototype, "permissions", void 0);
exports.AuthUser = AuthUser;
//# sourceMappingURL=auth-user.model.js.map