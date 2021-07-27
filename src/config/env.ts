/* eslint-disable radix */
import * as dotenv from 'dotenv';
import { IEnv as DbIEnv, env as dbEnv } from 'kalmia-sql-lib';

export interface IEnv {
  APP_SECRET: string;
}

/**
 * Load variables from .env.
 */
dotenv.config();
export const env: IEnv & DbIEnv = {
  ...dbEnv,
  /*
   * App secret for JWT.
   */
  APP_SECRET: process.env['APP_SECRET'] || 'notasecret',
};
