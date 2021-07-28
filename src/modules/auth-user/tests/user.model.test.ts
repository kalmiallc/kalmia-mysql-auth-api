import { MySqlUtil } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthDbTables } from '../../../config/types';
import { connectToDb, cleanDatabase, closeConnectionToDb } from '../../test-helpers/setup';
import { insertAuthUser } from '../../test-helpers/test-user';

describe('User - MySQL', () => {
  let databaseState;

  beforeAll(async () => {
    databaseState = new MySqlUtil(await connectToDb() as Pool);
  });

  afterAll(async () => {
    await cleanDatabase();
    await closeConnectionToDb();
  });

  it('Query should create and find one', async () => {
    const user = await insertAuthUser();

    const count = await databaseState.paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USERS};`,
    );
    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1,
        }),
      ]),
    );
  });


});
