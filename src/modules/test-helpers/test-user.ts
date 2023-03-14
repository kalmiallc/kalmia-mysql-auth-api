import { SerializeFor } from 'kalmia-sql-lib';
import { AuthUser } from '../auth-user/models/auth-user.model';

/**
 * Inserts new auth user into database.
 * @returns Created auth user.
 */
export async function insertAuthUser() {
  const user = new AuthUser({}).fake();
  const res = await user.create();
  return res.serialize(SerializeFor.ALL);
}
