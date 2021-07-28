/* eslint-disable radix */
import * as dotenv from 'dotenv';
import { IEnv as DbIEnv, env as dbEnv } from 'kalmia-sql-lib';

export interface IAuthEnv {
  APP_SECRET: string;
  ITEMS_PER_PAGE: number;
}

/**
 * Load variables from .env.
 */
dotenv.config();
export const env: IAuthEnv & DbIEnv = {
  ...dbEnv,

  /*
   * App secret for JWT.
   */
  APP_SECRET: process.env['APP_SECRET'] || 'notasecret',

  /*
   * Default items per page.
   */
  ITEMS_PER_PAGE: parseInt(process.env['ITEMS_PER_PAGE']) || 5,
};
