"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.env = void 0;
/* eslint-disable radix */
const dotenv = require("dotenv");
const kalmia_sql_lib_1 = require("kalmia-sql-lib");
/**
 * Load variables from .env.
 */
dotenv.config();
exports.env = Object.assign(Object.assign({}, kalmia_sql_lib_1.env), { 
    /*
     * App secret for JWT.
     */
    APP_SECRET: process.env['APP_SECRET'] || 'notasecret' });
//# sourceMappingURL=env.js.map