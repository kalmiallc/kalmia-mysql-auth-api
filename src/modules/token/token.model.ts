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

  @prop({
    parser: { resolver: integerParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
    validators: [],
  })
  public user_id: number;

  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
  })
  public subject: string;

  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.PROFILE],
    serializable: [SerializeFor.ADMIN]
  })
  public exp: string | number;

  @prop({
    parser: { resolver: dateParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE],
  })
  public expiresAt: Date;

  @prop({
    parser: { resolver: stringParser() },
    populatable: [PopulateFor.DB],
    serializable: [SerializeFor.PROFILE, SerializeFor.INSERT_DB],
  })
  public token: string;

  @prop({
    populatable: [],
    serializable: [],
  })
  public payload: any;

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
  public async invalidateToken(): Promise<boolean> {
    const sqlUtil = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool);
    const conn = await sqlUtil.start();
    try {
      const updateQuery = `UPDATE \`${this.tableName}\`  t
        SET t.status = 9
        WHERE t.token = @token`;
      const updateRes = await sqlUtil.paramExecute(
        updateQuery,
        {
          token: this.token
        },
        conn
      );
      await sqlUtil.commit(conn);
      return true;
    } catch (e) {
      await sqlUtil.rollback(conn);
    }
    return false;
  }

  public async validateToken(): Promise<any> {
    if (!this.token) {
      return null;
    }
    try {
      const payload = jwt.verify(this.token, env.APP_SECRET, {
        subject: this.subject,
      });
      if (payload) {
        const query = `
          SELECT t.token, t.user_id, t.status, t.expireTime
          FROM \`${this.tableName}\` t
          WHERE t.token = @token
            AND t.expireTime > CURRENT_TIMESTAMP
            AND t.status < ${DbModelStatus.DELETED}
        `;
        const data = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(query, { token: this.token });
        if (data && data.length) {
          return payload;
        }
      }
    } catch (e) {
    }
    return null;
  }
}
