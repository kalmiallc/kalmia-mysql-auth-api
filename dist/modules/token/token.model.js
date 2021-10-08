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
exports.Token = void 0;
/* eslint-disable @typescript-eslint/member-ordering */
const core_1 = require("@rawmodel/core");
const parsers_1 = require("@rawmodel/parsers");
const crypto_1 = require("crypto");
const jwt = require("jsonwebtoken");
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
const uuid_1 = require("uuid"); // timestamp uuid
const env_1 = require("../../config/env");
const types_1 = require("../../config/types");
/**
 * JWT token model.
 */
class Token extends kalmia_sql_lib_1.BaseModel {
    constructor() {
        super(...arguments);
        /**
         * Tokens database table.
         */
        this.tableName = types_1.AuthDbTables.TOKENS;
    }
    /**
     * Generates a new JWT and saves it to the database.
     * @param exp (optional) Time until expiration. Defaults to '1d'
     * @returns JWT
     */
    async generate(exp = '1d') {
        try {
            if (!exp) {
                exp = '1d';
            }
            if (!this.user_id) {
                this.user_id = null;
            }
            this.token = jwt.sign(Object.assign(Object.assign({}, this.payload), { tokenUuid: (0, uuid_1.v1)() }), env_1.env.APP_SECRET, {
                subject: this.subject,
                expiresIn: exp
            });
            // Get expiration date.
            const payload = jwt.decode(this.token);
            this.expiresAt = new Date(payload.exp * 1000 + Math.floor(Math.random() * 500));
            // Insert token into database.
            const createQuery = `INSERT INTO \`${this.tableName}\` (token, status, user_id, subject, expiresAt)
      VALUES
        (@token, @status, @user_id, @subject, @expiresAt)`;
            const sqlUtil = new kalmia_sql_lib_1.MySqlUtil(await this.db());
            const conn = await sqlUtil.start();
            await sqlUtil.paramExecute(createQuery, {
                token: this._tokenHash,
                user_id: this.user_id,
                subject: this.subject,
                expiresAt: this.expiresAt,
                status: kalmia_sql_lib_1.DbModelStatus.ACTIVE
            }, conn);
            const req = await sqlUtil.paramExecute('SELECT last_insert_id() AS id;', null, conn);
            this.id = req[0].id;
            await sqlUtil.commit(conn);
            return this.token;
        }
        catch (e) {
            return null;
        }
    }
    /**
     * If token in this.token exists in the database and is valid, returns a token with the same payload and refreshed expiration.
     * Expiration duration is the same as that of the original token.
     * @returns new token.
     */
    async refresh() {
        try {
            this.payload = jwt.decode(this.token);
            this.exp = this.payload.exp - this.payload.iat;
            delete this.payload.exp;
            delete this.payload.iat;
            this.subject = this.payload.sub;
            delete this.payload.sub;
            const data = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
        SELECT t.token, t.user_id, t.status, t.subject, t.expiresAt
        FROM \`${this.tableName}\` t
        WHERE t.token = @token
          AND t.expiresAt > CURRENT_TIMESTAMP
          AND t.status < ${kalmia_sql_lib_1.DbModelStatus.DELETED}
      `, { token: this._tokenHash });
            if (data && data.length) {
                this.populate(data[0], kalmia_sql_lib_1.PopulateFor.DB);
                return await this.generate(this.exp);
            }
        }
        catch (error) {
            return null;
        }
        return null;
    }
    /**
     * Populates model fields by token.
     *
     * @param token Token's token.
     */
    async populateByToken(token) {
        const data = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(`
      SELECT * FROM ${this.tableName}
      WHERE token = @token
    `, { token: (0, crypto_1.createHash)('sha256').update(token).digest('hex') });
        if (data && data.length) {
            return this.populate(Object.assign(Object.assign({}, data[0]), { token }), kalmia_sql_lib_1.PopulateFor.DB);
        }
        else {
            return this.reset();
        }
    }
    /**
     * Marks token as invalid in the database.
     * @returns boolean, whether the operation was successful or not.
     */
    async invalidateToken() {
        const sqlUtil = new kalmia_sql_lib_1.MySqlUtil(await this.db());
        const conn = await sqlUtil.start();
        try {
            await sqlUtil.paramExecute(`UPDATE \`${types_1.AuthDbTables.TOKENS}\`  t
        SET t.status = ${kalmia_sql_lib_1.DbModelStatus.DELETED}
        WHERE t.token = @token`, {
                token: this._tokenHash
            }, conn);
            this.status = kalmia_sql_lib_1.DbModelStatus.DELETED;
            await sqlUtil.commit(conn);
            return true;
        }
        catch (error) {
            await sqlUtil.rollback(conn);
        }
        return false;
    }
    /**
     * Invalidates all of the user's tokens with a specific subject.
     * @param userId User's ID.
     * @param type Token type
     * @returns Boolean if tokens were invalidated successfully.
     */
    async invalidateUserTokens(userId, type, connection) {
        if (!userId || !type) {
            return null;
        }
        const { singleTrans, sql, conn } = await this.getDbConnection(connection);
        try {
            await sql.paramExecute(`UPDATE \`${types_1.AuthDbTables.TOKENS}\`  t
        SET t.status = ${kalmia_sql_lib_1.DbModelStatus.DELETED}
        WHERE t.user_id = @userId
          AND t.subject = @type
          AND t.status < ${kalmia_sql_lib_1.DbModelStatus.DELETED}`, {
                userId,
                type
            }, conn);
            if (singleTrans) {
                await sql.commit(conn);
            }
            return true;
        }
        catch (error) {
            if (singleTrans) {
                await sql.rollback(conn);
            }
            throw new Error(error);
        }
    }
    /**
     * Validates token. If token is valid, returns its payload, otherwise null.
     * @param userId User's ID - if present the ownership of the token will also be validated.
     * @returns Token payload
     */
    async validateToken(userId) {
        if (!this.token) {
            return null;
        }
        try {
            const payload = jwt.verify(this.token, env_1.env.APP_SECRET, {
                subject: this.subject
            });
            if (!userId) {
                userId = 'NULL';
            }
            if (payload) {
                const query = `
          SELECT t.token, t.user_id, t.status, t.expiresAt
          FROM \`${types_1.AuthDbTables.TOKENS}\` t
          WHERE t.token = @token
            AND t.expiresAt > CURRENT_TIMESTAMP
            AND t.status < ${kalmia_sql_lib_1.DbModelStatus.DELETED}
            AND (@userId IS NULL OR t.user_id = @userId)
        `;
                const data = await new kalmia_sql_lib_1.MySqlUtil(await this.db()).paramExecute(query, {
                    token: this._tokenHash,
                    userId
                });
                if (data && data.length) {
                    return payload;
                }
            }
        }
        catch (error) {
            return null;
        }
        return null;
    }
}
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.integerParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE, kalmia_sql_lib_1.SerializeFor.INSERT_DB],
        validators: []
    }),
    __metadata("design:type", Number)
], Token.prototype, "user_id", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE, kalmia_sql_lib_1.SerializeFor.INSERT_DB]
    }),
    __metadata("design:type", String)
], Token.prototype, "subject", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.PROFILE],
        serializable: [kalmia_sql_lib_1.SerializeFor.ADMIN]
    }),
    __metadata("design:type", Object)
], Token.prototype, "exp", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.dateParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE]
    }),
    __metadata("design:type", Date)
], Token.prototype, "expiresAt", void 0);
__decorate([
    (0, core_1.prop)({
        parser: { resolver: (0, parsers_1.stringParser)() },
        populatable: [kalmia_sql_lib_1.PopulateFor.DB],
        serializable: [kalmia_sql_lib_1.SerializeFor.PROFILE]
    }),
    __metadata("design:type", String)
], Token.prototype, "token", void 0);
__decorate([
    (0, core_1.prop)({
        getter() {
            return this.token ? (0, crypto_1.createHash)('sha256').update(this.token).digest('hex') : null;
        }
    }),
    __metadata("design:type", String)
], Token.prototype, "_tokenHash", void 0);
__decorate([
    (0, core_1.prop)({
        populatable: [],
        serializable: []
    }),
    __metadata("design:type", Object)
], Token.prototype, "payload", void 0);
exports.Token = Token;
//# sourceMappingURL=token.model.js.map