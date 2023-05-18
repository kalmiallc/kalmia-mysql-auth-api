import { ICommonEnv } from 'kalmia-common-lib';
import { IEnv as DbIEnv } from 'kalmia-sql-lib';
export interface IAuthEnv {
    APP_SECRET: string;
    RSA_JWT_PK: string;
    JWT_AUDIENCE: string;
}
export declare const env: IAuthEnv & DbIEnv & ICommonEnv;
//# sourceMappingURL=env.d.ts.map