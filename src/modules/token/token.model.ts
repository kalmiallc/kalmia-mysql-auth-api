/* eslint-disable @typescript-eslint/member-ordering */
import { prop } from '@rawmodel/core';
import { dateParser, integerParser, stringParser } from '@rawmodel/parsers';
import { BaseModel, DbModelStatus, MySqlConnManager, MySqlUtil, PopulateFor, SerializeFor } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthDbTables } from '../../config/types';
import * as jwt from 'jsonwebtoken';
import { env } from '../../config/env';
import { v1 as uuid_v1 } from 'uuid'; // timestamp uuid

export class Token extends BaseModel {
  tableName = AuthDbTables.TOKENS;

  /**
   * Token's user_id property definition. If token is connected to a specific user, populate this with their id.
   */
  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
    validators: [],
  })
  public user_id: number;

  /**
   * Token's subject property definition. Populate this with the JWT subject, which is used to discern token purposes.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
  })
  public subject: string;

  /**
   * Token's exp property definition. Used for defining token expiration. Defaults to '1d'.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.PROFILE],
    serializable: [SerializeFor.ADMIN]
  })
  public exp: string | number;

  /**
   * Token's expiresAt property definition. This is calculated and saved to the database so it is known when the token will expire. This also enables querying. Do not populate this, use exp.
   */
  @prop({
    parser: { resolver: dateParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE],
  })
  public expiresAt: Date;

  /**
   * Token's token property definition. Populate this if you need to validate, invalidate, or refresh a token. This is also where newly-generated tokens are assigned.
   */
  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
  })
  public token: string;

  /**
   * Token's payload property definition. This is the data that will be stored in the token and will be retrieved from the token. Populate this if you wish to generate a token.
   */
  @prop({
    populatable: [],
    serializable: [],
  })
  public payload: any;

  /**
   * Generates a new JWT and saves it to the database.
   * @param exp (optional) Time until expiration. Defaults to '1d'
   * @returns JWT
   */
  public async generate(exp: string | number = '1d'): Promise<string> {
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
        env.APP_SECRET,
        {
          subject: this.subject,
          expiresIn: exp
        }
      );

      // get expiration date
      const payload: any = jwt.decode(this.token);
      this.expiresAt = new Date(payload.exp * 1000 + Math.floor(Math.random() * 500));

      // insert token into database
      const createQuery = `INSERT INTO \`${this.tableName}\` (token, status, user_id, subject, expiresAt)
      VALUES
        (@token, @status, @user_id, @subject, @expiresAt)`;
      const sqlUtil = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool);
      const conn = await sqlUtil.start();
      await sqlUtil.paramExecute(
        createQuery,
        {
          token: this.token,
          user_id: this.user_id,
          subject: this.subject,
          expiresAt: this.expiresAt,
          status: DbModelStatus.ACTIVE,
        },
        conn
      );
      const req = await sqlUtil.paramExecute('SELECT last_insert_id() AS id;', null, conn);
      this.id = req[0].id;
      await sqlUtil.commit(conn);
      return this.token;
    } catch (e) {
      return null;
    }
  }

  /**
   * If token in this.token exists in the database and is valid, returns a token with the same payload and refreshed expiration. Expiration duration is the same as that of the original token.
   * @returns new token.
   */
  public async refresh(): Promise<string> {
    try {
      this.payload = jwt.decode(this.token);
      this.exp = this.payload.exp - this.payload.iat;
      // eslint-disable-next-line @typescript-eslint/no-unused-expressions
      delete this.payload.exp, this.payload.iat;
      this.subject = this.payload.sub;
      delete this.payload.sub;

      const query = `
        SELECT t.token, t.user_id, t.status, t.subject, t.expiresAt
        FROM \`${this.tableName}\` t
        WHERE t.token = @token
          AND t.expiresAt > CURRENT_TIMESTAMP
          AND t.status < ${DbModelStatus.DELETED}
      `;
      const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, { token: this.token });
      if (data && data.length) {
        this.populate(data[0], PopulateFor.DB);
        return await this.generate(this.exp);
      }
    } catch (e) {
    }
    return null;
  }

  /**
   * Populates model fields by token.
   *
   * @param token Token's token.
   */
  public async populateByToken(token: string): Promise<this> {
    const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `
      SELECT * FROM ${this.tableName}
      WHERE token = @token
    `,
      { token }
    );

    if (data && data.length) {
      return this.populate(data[0], PopulateFor.DB);
    } else {
      return this.reset();
    }
  }

  /**
   * Marks token as invalid in the database.
   * @returns boolean, whether the operation was successful or not.
   */
  public async invalidateToken(): Promise<boolean> {
    const sqlUtil = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool);
    const conn = await sqlUtil.start();

    try {
      const updateQuery = `UPDATE \`${this.tableName}\`  t
        SET t.status = ${DbModelStatus.DELETED}
        WHERE t.token = @token`;

      await sqlUtil.paramExecute(
        updateQuery,
        {
          token: this.token
        },
        conn
      );

      this.status = DbModelStatus.DELETED;
      await sqlUtil.commit(conn);
      return true;
    } catch (e) {
      await sqlUtil.rollback(conn);
    }
    return false;
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
      const payload = jwt.verify(
        this.token,
        env.APP_SECRET,
        {
          subject: this.subject,
        }
      );

      if (payload) {
        const query = `
          SELECT t.token, t.user_id, t.status, t.expiresAt
          FROM \`${this.tableName}\` t
          WHERE t.token = @token
            AND t.expiresAt > CURRENT_TIMESTAMP
            AND t.status < ${DbModelStatus.DELETED}
            AND (@userId IS NULL OR t.user_id = @userId)
        `;

        const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, {
          token: this.token,
          userId
        });

        if (data && data.length) {
          return payload;
        }
      }
    } catch (e) {
    }
    return null;
  }
}
