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
exports.Role = void 0;
/* eslint-disable @typescript-eslint/member-ordering */
const core_1 = require("@rawmodel/core");
const parsers_1 = require("@rawmodel/parsers");
const validators_1 = require("@rawmodel/validators");
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const types_1 = require("../../../config/types");
const role_permission_model_1 = require("./role-permission.model");
/**
 * Role model.
 */
class Role extends kalmia_sql_lib_1.BaseModel {
    constructor() {
        super(...arguments);
        /**
         * Roles table.
         */
        this.tableName = types_1.AuthDbTables.ROLES;
    }
    /**
     * Checks whether a role has certain permissions
     * @param pass PermissionPass to check for. Role must meet or exceed permissions.
     * @returns boolean, whether role has permission.
     */
    hasPermission(pass) {
        for (const rolePermission of this.rolePermissions) {
            if (rolePermission.hasPermission(pass)) {
                return true;
            }
        }
        return false;
    }
    /**
     * Populates role's role permissions.
     *
     * @param conn (optional) database connection.
     * @returns Same instance with freshly populated role permissions.
     */
    async populatePermissions(conn) {
        this.rolePermissions = [];
        const rows = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT 
        rp.*
      FROM ${types_1.AuthDbTables.ROLE_PERMISSIONS} rp
      WHERE rp.role_id = @roleId
      ORDER BY rp.role_id;
    `, { roleId: this.id }, conn);
        for (const row of rows) {
            this.rolePermissions = [
                ...this.rolePermissions,
                new role_permission_model_1.RolePermission({}).populate(Object.assign(Object.assign({}, row), { id: null }), kalmia_sql_lib_1.PopulateFor.DB)
            ];
        }
        return this;
    }
    /**
     * Populates role fields by name.
     *
     * @param name Role's name.
     */
    async populateByName(name) {
        const res = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
        SELECT * FROM ${this.tableName}
        WHERE name = @name
      `, { name });
        if (!res.length) {
            return this.reset();
        }
        this.populate(res[0]);
        await this.populatePermissions();
        return this;
    }
    /**
     * Populates role fields by id.
     *
     * @param id Role's id.
     */
    async populateById(id, conn) {
        const res = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT * FROM ${this.tableName}
      WHERE id = @id
    `, { id }, conn);
        if (!res.length) {
            return this.reset();
        }
        this.populate(res[0]);
        await this.populatePermissions(conn);
        return this;
    }
    /**
     * Deletes role permissions from the role.
     * @param permissionIds List of role permissions.
     */
    async deleteRolePermissions(permissionIds) {
        try {
            await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
          DELETE rp
          FROM ${types_1.AuthDbTables.ROLE_PERMISSIONS} rp
          WHERE rp.role_id = @id AND
            rp.permission_id IN (${permissionIds.join(', ')})
        `, {
                id: this.id
            });
            this.rolePermissions = this.rolePermissions.filter((rp) => permissionIds.indexOf(rp.permission_id) === -1);
        }
        catch (error) {
            throw new Error(error);
        }
    }
    /**
     * Returns a list of roles based on the given filter.
     *
     * @param filter Object used for filtering.
     * @returns List of filtered roles.
     */
    async getList(filter) {
        // Set default values or null for all params that we pass to sql query.
        const defaultParams = {
            id: null,
            search: null
        };
        // Map url query with sql fields.
        const fieldMap = {
            id: 'u.id'
        };
        const { params, filters } = (0, kalmia_sql_lib_1.getQueryParams)(defaultParams, 'r', fieldMap, filter);
        const sqlQuery = {
            qSelect: `
        SELECT
          ${this.getSelectColumns('r')},
          r.name,
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
        `,
            qFrom: `
        FROM (SELECT * FROM \`${types_1.AuthDbTables.ROLES}\` LIMIT ${filters.limit} OFFSET ${filters.offset}) r
        LEFT JOIN \`${types_1.AuthDbTables.ROLE_PERMISSIONS}\` rp
          ON r.id = rp.role_id
        WHERE
          (@id IS NULL OR r.id = @id)
          AND (@search IS NULL
            OR r.name LIKE CONCAT('%', @search, '%')
          )
        `,
            qGroup: `
        GROUP BY
          ${this.getSelectColumns('r')},
          r.name,
          rp.name,
          rp.role_id,
          rp.permission_id,
          rp.read,
          rp.write,
          rp.execute,
          rp.status,
          rp._createTime,
          rp._updateTime,
          rp._createUser,
          rp._updateUser
        `,
            qFilter: `
        ORDER BY ${filters.orderStr};
      `
        };
        const sql = await this.sql();
        const res = await (0, kalmia_sql_lib_1.selectAndCountQuery)(sql, sqlQuery, params, 'r.id');
        const rows = res.items;
        let roles = [];
        for (const row of rows) {
            let role = roles.find((r) => r.id === row.id);
            if (!role) {
                role = new Role().populate(row, kalmia_sql_lib_1.PopulateFor.DB);
                roles = [...roles, role];
            }
            const permission = new role_permission_model_1.RolePermission({}).populate(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign(Object.assign({}, row), (row.rpName ? { name: row.rpName } : { name: null })), (row.rpStatus ? { status: row.rpStatus } : { status: null })), (row.rpCreateTime ? { _createTime: row.rpCreateTime } : { _createTime: null })), (row.rpUpdateTime ? { _updateTime: row.rpUpdateTime } : { _updateTime: null })), (row.rpCreateUser ? { _createUser: row.rpCreateUser } : { _createUser: null })), (row.rpUpdateUser ? { _updateUser: row.rpUpdateUser } : { _updateUser: null })), { id: null }), kalmia_sql_lib_1.PopulateFor.DB);
            if (permission.exists()) {
                role.rolePermissions = [...role.rolePermissions, permission];
            }
        }
        const total = await sql
            .paramExecute(`
      SELECT COUNT(*) AS 'count'
      FROM ${types_1.AuthDbTables.ROLES} r
      WHERE
        (@id IS NULL OR r.id = @id)
        AND (@search IS NULL
          OR r.name LIKE CONCAT('%', @search, '%')
        )
      `, params)
            .then((totalRes) => { var _a; return (((_a = totalRes[0]) === null || _a === void 0 ? void 0 : _a.count) ? Number(totalRes[0].count) : res.total); });
        return {
            items: roles,
            total
        };
    }
    /**
     * Hard deletes role, its role permissions and user roles from the database.
     * @param options Delete options.
     * @returns Deleted role (this).
     */
    async delete(options = {}) {
        const { singleTrans, sql, conn } = await this.getDbConnection(options.conn);
        try {
            const deleteUserRolesQuery = `
        DELETE ur
        FROM ${types_1.AuthDbTables.USER_ROLES} ur
        JOIN ${types_1.AuthDbTables.ROLES} r
          ON ur.role_id = r.id
        WHERE r.id = @roleId
        `;
            await sql.paramExecute(deleteUserRolesQuery, { roleId: this.id }, conn);
            const deleteRolePermissionsQuery = `
        DELETE rp
        FROM ${types_1.AuthDbTables.ROLE_PERMISSIONS} rp
        JOIN ${types_1.AuthDbTables.ROLES} r
          ON rp.role_id = r.id
        WHERE r.id = @roleId
      `;
            await sql.paramExecute(deleteRolePermissionsQuery, { roleId: this.id }, conn);
            const deleteRoleQuery = `
        DELETE FROM ${types_1.AuthDbTables.ROLES}
        WHERE id = @roleId
      `;
            await sql.paramExecute(deleteRoleQuery, { roleId: this.id }, conn);
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
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE, kalmia_sql_lib_1.SerializeFor.ADMIN]
    }),
    __metadata("design:type", Number)
], Role.prototype, "id", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB, kalmia_sql_lib_1.PopulateFor.ADMIN],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE, kalmia_sql_lib_1.SerializeFor.ADMIN, kalmia_sql_lib_1.SerializeFor.INSERT_DB, kalmia_sql_lib_1.SerializeFor.UPDATE_DB],
        validators: [
            {
                resolver: (0, validators_1.presenceValidator)(),
                code: types_1.AuthValidatorErrorCode.ROLE_NAME_NOT_PRESENT
            },
            {
                resolver: (0, kalmia_sql_lib_1.uniqueFieldWithIdValidator)(types_1.AuthDbTables.ROLES, 'name'),
                code: types_1.AuthValidatorErrorCode.ROLE_NAME_ALREADY_TAKEN
            }
        ]
    }),
    __metadata("design:type", String)
], Role.prototype, "name", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: role_permission_model_1.RolePermission, array: true },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE, kalmia_sql_lib_1.SerializeFor.ADMIN],
        defaultValue: () => [],
        emptyValue: () => []
    }),
    __metadata("design:type", Array)
], Role.prototype, "rolePermissions", void 0);
exports.Role = Role;
//# sourceMappingURL=role.model.js.map