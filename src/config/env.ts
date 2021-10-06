/* eslint-disable radix */
import * as dotenv from 'dotenv';
import { IEnv as DbIEnv, env as dbEnv, ICommonEnv } from 'kalmia-sql-lib';

export interface IAuthEnv {
  APP_SECRET: string;
}

/**
 * Load variables from .env.
 */
dotenv.config();
export const env: IAuthEnv & DbIEnv & ICommonEnv = {
  ...dbEnv,

  /*
   * App secret for JWT.
   */
  APP_SECRET: process.env['APP_SECRET'] || 'notasecret'
};
