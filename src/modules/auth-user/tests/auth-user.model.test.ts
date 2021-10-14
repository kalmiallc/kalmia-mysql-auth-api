import { MySqlUtil } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthDbTables } from '../../../config/types';
import { cleanDatabase, closeConnectionToDb, connectToDb } from '../../test-helpers/setup';
import { insertAuthUser } from '../../test-helpers/test-user';

describe('Auth user model tests', () => {
  let databaseState: MySqlUtil;

  beforeAll(async () => {
    databaseState = new MySqlUtil((await connectToDb()) as Pool);
  });

  afterAll(async () => {
    await cleanDatabase();
    await closeConnectionToDb();
  });

  it('Query should create and find one', async () => {
    const user = await insertAuthUser();

    const count = await databaseState.paramExecute(`SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USERS};`);
    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });
});
