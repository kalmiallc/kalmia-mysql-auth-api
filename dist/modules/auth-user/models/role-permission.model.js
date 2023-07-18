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
exports.RolePermission = void 0;
/* eslint-disable @typescript-eslint/indent */
/* eslint-disable @typescript-eslint/member-ordering */
const core_1 = require("@rawmodel/core");
const parsers_1 = require("@rawmodel/parsers");
const validators_1 = require("@rawmodel/validators");
const kalmia_common_lib_1 = require("kalmia-common-lib");
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../../config/types");
/**
 * Role permission model.
 */
class RolePermission extends kalmia_sql_lib_1.BaseModel {
    constructor(data) {
        super(data);
        /**
         * Role permissions table.
         */
        this.tableName = types_1.AuthDbTables.ROLE_PERMISSIONS;
    }
    /**
     * Tells if the model represents a document stored in the database.
     */
    exists() {
        return !!this.role_id && !!this.permission_id && this.status !== kalmia_sql_lib_1.DbModelStatus.DELETED;
    }
    /**
     * Tells whether a role permission meets or exceeds a certain permission requirement.
     * @param pass PermissionPass permission requirement.
     * @returns boolean, whether role permission has required permission
     */
    hasPermission(pass) {
        return pass.permission === this.permission_id && this[pass.type] && (!pass.level || pass.level <= this[pass.type]);
    }
    /**
     * Checks whether a certain role permission exists in the db.
     * @returns Promise<boolean>
     */
    async existsInDb() {
        const data = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT * FROM ${this.tableName}
      WHERE role_id = @role_id
        AND permission_id = @permission_id
    `, { role_id: this.role_id, permission_id: this.permission_id });
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
    async populateByIds(roleId, permissionId, conn) {
        if (!roleId || !permissionId) {
            return this.reset();
        }
        const rows = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT * FROM ${this.tableName}
      WHERE role_id = @roleId
        AND permission_id = @permissionId
    `, { roleId, permissionId }, conn);
        if (!(rows === null || rows === void 0 ? void 0 : rows.length)) {
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
    async update(options = {}) {
        var _a, _b;
        if (!(options === null || options === void 0 ? void 0 : options.context)) {
            options.context = this.getContext();
        }
        if ((_b = (_a = options === null || options === void 0 ? void 0 : options.context) === null || _a === void 0 ? void 0 : _a.user) === null || _b === void 0 ? void 0 : _b.id) {
            this._updateUser = options.context.user.id;
        }
        const serializedModel = this.serialize(kalmia_sql_lib_1.SerializeFor.UPDATE_DB);
        delete serializedModel.id;
        delete serializedModel._createTime;
        delete serializedModel._updateTime;
        const { singleTrans, sql, conn } = await this.getDbConnection(options.conn);
        try {
            const updateQuery = `
      UPDATE \`${types_1.AuthDbTables.ROLE_PERMISSIONS}\`
      SET
        ${Object.keys(serializedModel)
                .map((x) => `\`${x}\` = @${x}`)
                .join(',\n')}
      WHERE role_id = @roleId
        AND permission_id = @permissionId
      `;
            await sql.paramExecute(updateQuery, Object.assign(Object.assign({}, serializedModel), { roleId: this.role_id, permissionId: this.permission_id }), conn);
            this._updateTime = new Date();
            if (singleTrans) {
                await sql.commitAndRelease(conn);
            }
        }
        catch (error) {
            if (singleTrans) {
                await sql.rollbackAndRelease(conn);
            }
            throw new Error(error);
        }
        return this;
    }
}
exports.RolePermission = RolePermission;
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_ROLE_ID_NOT_PRESENT
            }
        ]
    }),
    __metadata("design:type", Number)
], RolePermission.prototype, "role_id", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_PERMISSION_ID_NOT_PRESENT
            }
        ]
    }),
    __metadata("design:type", Number)
], RolePermission.prototype, "permission_id", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_NAME_NOT_PRESENT
            }
        ]
    }),
    __metadata("design:type", String)
], RolePermission.prototype, "name", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN, kalmia_sql_lib_1.PopulateFor.ALL],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB, kalmia_sql_lib_1.SerializeFor.UPDATE_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_SET
            },
            {
                resolver: (0, kalmia_common_lib_1.enumInclusionValidator)(types_1.PermissionLevel),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_VALID
            }
        ],
        fakeValue: () => types_1.PermissionLevel.ALL,
        defaultValue: () => types_1.PermissionLevel.NONE
    }),
    __metadata("design:type", Number)
], RolePermission.prototype, "read", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN, kalmia_sql_lib_1.PopulateFor.ALL],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB, kalmia_sql_lib_1.SerializeFor.UPDATE_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_SET
            },
            {
                resolver: (0, kalmia_common_lib_1.enumInclusionValidator)(types_1.PermissionLevel),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID
            }
        ],
        fakeValue: () => types_1.PermissionLevel.ALL,
        defaultValue: () => types_1.PermissionLevel.NONE
    }),
    __metadata("design:type", Number)
], RolePermission.prototype, "write", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN, kalmia_sql_lib_1.PopulateFor.ALL],
        serializable: [kalmia_sql_lib_1.SerializeFor.ALL, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB, kalmia_sql_lib_1.SerializeFor.UPDATE_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET
            },
            {
                resolver: (0, kalmia_common_lib_1.enumInclusionValidator)(types_1.PermissionLevel),
                code: types_1.AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID
            }
        ],
        fakeValue: () => types_1.PermissionLevel.ALL,
        defaultValue: () => types_1.PermissionLevel.NONE
    }),
    __metadata("design:type", Number)
], RolePermission.prototype, "execute", void 0);
//# sourceMappingURL=role-permission.model.js.map