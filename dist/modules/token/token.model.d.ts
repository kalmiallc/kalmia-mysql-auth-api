import { BaseModel } from 'kalmia-sql-lib';
import { PoolConnection } from 'mysql2/promise';
import { AuthDbTables, AuthJwtTokenType } from '../../config/types';
/**
 * JWT token model.
 */
export declare class Token extends BaseModel {
    /**
     * Tokens database table.
     */
    tableName: AuthDbTables;
    /**
     * Token's user_id property definition. If token is connected to a specific user, populate this with their id.
     */
    user_id: number;
    /**
     * Token's subject property definition. Populate this with the JWT subject, which is used to discern token purposes.
     */
    subject: string;
    /**
     * Token's exp property definition. Used for defining token expiration. Defaults to '1d'.
     */
    exp: string | number;
    /**
     * Token's expiresAt property definition.
     * This is calculated and saved to the database so it is known when the token will expire.
     * This also enables querying. Do not populate this, use exp.
     */
    expiresAt: Date;
    /**
     * Token's token property definition.
     * Populate this if you need to validate, invalidate, or refresh a token. This is also where newly-generated tokens are assigned.
     */
    token: string;
    /**
     * Token's hash property definition.
     * This property is used for saving the hashed token in the database - actual value of the token is never saved.
     */
    private _tokenHash;
    /**
     * Token's payload property definition.
     * This is the data that will be stored in the token and will be retrieved from the token.
     * Populate this if you wish to generate a token.
     */
    payload: any;
    /**
     * Generates a new JWT and saves it to the database.
     * @param exp (optional) Time until expiration. Defaults to '1d'
     * @returns JWT
     */
    generate(exp?: string | number): Promise<string>;
    /**
     * If token in this.token exists in the database and is valid, returns a token with the same payload and refreshed expiration.
     * Expiration duration is the same as that of the original token.
     * @returns new token.
     */
    refresh(): Promise<string>;
    /**
     * Populates model fields by token.
     *
     * @param token Token's token.
     */
    populateByToken(token: string): Promise<this>;
    /**
     * Marks token as invalid in the database.
     * @returns boolean, whether the operation was successful or not.
     */
    invalidateToken(): Promise<boolean>;
    /**
     * Invalidates all of the user's tokens with a specific subject.
     * @param userId User's ID.
     * @param type Token type
     * @returns Boolean if tokens were invalidated successfully.
     */
    invalidateUserTokens(userId: number, type: AuthJwtTokenType, connection?: PoolConnection): Promise<boolean>;
    /**
     * Validates token. If token is valid, returns its payload, otherwise null.
     * @param userId User's ID - if present the ownership of the token will also be validated.
     * @returns Token payload
     */
    validateToken(userId?: string): Promise<any>;
}
//# sourceMappingURL=token.model.d.ts.map