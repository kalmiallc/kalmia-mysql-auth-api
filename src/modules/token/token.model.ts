/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { dateParser, integerParser, stringParser } from '@rawmodel/parsers';
import { createHash } from 'crypto';
import * as jwt from 'jsonwebtoken';
import { BaseModel, DbModelStatus, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { v1 as uuid_v1 } from 'uuid'; // timestamp uuid
import { env } from '../../config/env';
import { AuthDbTables, AuthJwtTokenType } from '../../config/types';

/**
 * JWT token model.
 */
export class Token extends BaseModel {
  /**
   * Tokens database table.
   */
  tableName = AuthDbTables.TOKENS;

  /**
   * Token's user_id property definition. If token is connected to a specific user, populate this with their id.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB],
    validators: []
    })
  public user_id: number;

  /**
   * Token's subject property definition. Populate this with the JWT subject, which is used to discern token purposes.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL, SerializeFor.INSERT_DB]
    })
  public subject: string;

  /**
   * Token's exp property definition. Used for defining token expiration. Defaults to '1d'.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.ALL],
    serializable: [SerializeFor.ADMIN]
    })
  public exp: string | number;

  /**
   * Token's expiresAt property definition.
   * This is calculated and saved to the database so it is known when the token will expire.
   * This also enables querying. Do not populate this, use exp.
   */
  @prop({
    parser: { resolver: dateParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL]
    })
  public expiresAt: Date;

  /**
   * Token's token property definition.
   * Populate this if you need to validate, invalidate, or refresh a token. This is also where newly-generated tokens are assigned.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.ALL]
    })
  public token: string;

  /**
   * Token's hash property definition.
   * This property is used for saving the hashed token in the database - actual value of the token is never saved.
   */
  @prop({
    getter() {
    return this.token ? createHash('sha256').update(this.token).digest('hex') : null;
    }
    })
  private _tokenHash: string;

  /**
   * Token's payload property definition.
   * This is the data that will be stored in the token and will be retrieved from the token.
   * Populate this if you wish to generate a token.
   */
  @prop({
    populatable: [],
    serializable: []
    })
  public payload: any;


  /**
   * Generates a new JWT and saves it to the database.
   * @param exp (optional) Time until expiration. Defaults to '1d'
   * @returns JWT
   */
  public async generate(exp: string | number = '1d', connection?: PoolConnection): Promise<string> {
    const { singleTrans, sql, conn } = await this.getDbConnection(connection);

    try {
      if (!exp) {
        exp = '1d';
      }

      if (!this.user_id) {
        this.user_id = null;
      }

      this.token = jwt.sign(
        {
          ...this.payload,
          tokenUuid: uuid_v1()
        },
        env.RSA_JWT_PK || env.APP_SECRET,
        {
          subject: this.subject,
          expiresIn: exp,
          algorithm: env.RSA_JWT_PK ? 'RS256' : null
        },
      
      );

      // Get expiration date.
      const payload: any = jwt.decode(this.token);
      this.expiresAt = new Date(payload.exp * 1000 + Math.floor(Math.random() * 500));

      // Insert token into database.
      const createQuery = `INSERT INTO \`${this.tableName}\` (token, status, user_id, subject, expiresAt)
      VALUES
        (@token, @status, @user_id, @subject, @expiresAt)`;

      await sql.paramExecute(
        createQuery,
        {
          token: this._tokenHash,
          user_id: this.user_id,
          subject: this.subject,
          expiresAt: this.expiresAt,
          status: DbModelStatus.ACTIVE
        },
        conn
      );
      const req = await sql.paramExecute('SELECT last_insert_id() AS id;', null, conn);
      this.id = req[0].id;

      if (singleTrans) {
        await sql.commit(conn);
      }
      return this.token;
    } catch (e) {
      if (singleTrans) {
        await sql.rollback(conn);
      }
      return null;
    }
  }

  /**
   * If token in this.token exists in the database and is valid, returns a token with the same payload and refreshed expiration.
   * Expiration duration is the same as that of the original token.
   * @returns new token.
   */
  public async refresh(): Promise<string> {
    try {
      this.payload = jwt.decode(this.token);

      this.exp = this.payload.exp - this.payload.iat;
      delete this.payload.exp;
      delete this.payload.iat;

      this.subject = this.payload.sub;
      delete this.payload.sub;

      const data = await new MySqlUtil(await this.db()).paramExecute(
        `
        SELECT t.token, t.user_id, t.status, t.subject, t.expiresAt
        FROM \`${this.tableName}\` t
        WHERE t.token = @token
          AND t.expiresAt > CURRENT_TIMESTAMP
          AND t.status < ${DbModelStatus.DELETED}
      `,
        { token: this._tokenHash }
      );

      if (data && data.length) {
        this.populate(data[0], PopulateFor.DB);
        return await this.generate(this.exp);
      }
    } catch (error) {
      return null;
    }
    return null;
  }

  /**
   * Populates model fields by token.
   *
   * @param token Token's token.
   */
  public async populateByToken(token: string): Promise<this> {
    const data = await new MySqlUtil(await this.db()).paramExecute(
      `
      SELECT * FROM ${this.tableName}
      WHERE token = @token
    `,
      { token: createHash('sha256').update(token).digest('hex') }
    );

    if (data && data.length) {
      return this.populate({ ...data[0], token }, PopulateFor.DB);
    } else {
      return this.reset();
    }
  }

  /**
   * Marks token as invalid in the database.
   * @returns boolean, whether the operation was successful or not.
   */
  public async invalidateToken(connection?: PoolConnection): Promise<boolean> {
    const { singleTrans, sql, conn } = await this.getDbConnection(connection);

    try {
      await sql.paramExecute(
        `UPDATE \`${AuthDbTables.TOKENS}\`  t
        SET t.status = ${DbModelStatus.DELETED}
        WHERE t.token = @token`,
        {
          token: this._tokenHash
        },
        conn
      );

      this.status = DbModelStatus.DELETED;
      if (singleTrans) {
        await sql.commit(conn);
      }
      return true;
    } catch (error) {
      if (singleTrans) {
        await sql.rollback(conn);
      }
    }
    return false;
  }

  /**
   * Invalidates all of the user's tokens with a specific subject.
   * @param userId User's ID.
   * @param type Token type
   * @returns Boolean if tokens were invalidated successfully.
   */
  public async invalidateUserTokens(userId: number, type: AuthJwtTokenType, connection?: PoolConnection): Promise<boolean> {
    if (!userId || !type) {
      return null;
    }

    const { singleTrans, sql, conn } = await this.getDbConnection(connection);
    try {
      await sql.paramExecute(
        `UPDATE \`${AuthDbTables.TOKENS}\`  t
        SET t.status = ${DbModelStatus.DELETED}
        WHERE t.user_id = @userId
          AND t.subject = @type
          AND t.status < ${DbModelStatus.DELETED}`,
        {
          userId,
          type
        },
        conn
      );

      if (singleTrans) {
        await sql.commit(conn);
      }
      return true;
    } catch (error) {
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
  public async validateToken(userId?: string): Promise<any> {
    if (!this.token) {
      return null;
    }

    try {
      const payload = jwt.verify(this.token, env.RSA_JWT_PK || env.APP_SECRET, {
        subject: this.subject,
        algorithms: env.RSA_JWT_PK ? ['RS256'] : null
      });

      if (payload) {
        const query = `
          SELECT t.token, t.user_id, t.status, t.expiresAt
          FROM \`${AuthDbTables.TOKENS}\` t
          WHERE t.token = @token
            AND t.expiresAt > CURRENT_TIMESTAMP
            AND t.status < ${DbModelStatus.DELETED}
            AND (@userId IS NULL OR t.user_id = @userId)
        `;

        const data = await new MySqlUtil(await this.db()).paramExecute(query, {
          token: this._tokenHash,
          userId
        });

        if (data && data.length) {
          return payload;
        }
      }
    } catch (error) {
      return null;
    }
    return null;
  }
}
