/* eslint-disable radix */
import * as dotenv from 'dotenv';
import { ICommonEnv } from 'kalmia-common-lib';
import { env as dbEnv, IEnv as DbIEnv } from 'kalmia-sql-lib';

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
