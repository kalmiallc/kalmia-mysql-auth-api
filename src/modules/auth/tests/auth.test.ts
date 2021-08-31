import * as faker from 'faker';
import * as jwt from 'jsonwebtoken';
import { DbModelStatus, MySqlConnManager, MySqlUtil } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { env } from '../../../config/env';
import {
  AuthAuthenticationErrorCode,
  AuthBadRequestErrorCode,
  AuthDbTables,
  AuthJwtTokenType,
  AuthResourceNotFoundErrorCode,
  AuthSystemErrorCode,
  AuthValidatorErrorCode,
  PermissionLevel,
  PermissionType
} from '../../../config/types';
import { cleanDatabase, closeConnectionToDb, connectToDb } from '../../test-helpers/setup';
import { insertAuthUser } from '../../test-helpers/test-user';
import { Auth } from '../auth';
import { insertRoleWithPermissions } from '../../test-helpers/permission';

describe('Auth', () => {
  beforeEach(async () => {
    await connectToDb();
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await closeConnectionToDb();
  });

  it('Create user and get by ID', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const userRes = await auth.getAuthUserById(user.id);
    expect(user.id).toBe(userRes?.data?.id);
    expect(user.email).toBe(userRes?.data?.email);
  });

  it('Try finding non-existing user by ID and return error', async () => {
    const auth = Auth.getInstance();
    const userRes = await auth.getAuthUserById(123);
    expect(userRes.status).toEqual(false);
    expect(userRes.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
  });

  it('Create user and get by email', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const userRes = await auth.getAuthUserByEmail(user.email);
    expect(user.id).toBe(userRes?.data?.id);
    expect(user.email).toBe(userRes?.data?.email);
  });

  it('Try finding non-existing user by email and return empty user', async () => {
    const auth = Auth.getInstance();
    const userRes = await auth.getAuthUserByEmail('non.existent@example.com');
    expect(userRes.status).toEqual(false);
    expect(userRes.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
  });

  it('[HELPER] Query should create and find 1 role with 2 permissions', async () => {
    await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );
    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const permissionCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
    );
    expect(permissionCount.length).toBe(1);
    expect(permissionCount).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 2
        })
      ])
    );
  });

  it('Should add role to user', async () => {
    const user = await insertAuthUser();
    const role = await insertRoleWithPermissions(faker.lorem.words(3), [
      {
        permission_id: 1,
        name: faker.lorem.words(1),
        read: PermissionLevel.OWN,
        write: PermissionLevel.NONE,
        execute: PermissionLevel.NONE
      }
    ]);
    const auth = Auth.getInstance();
    await auth.grantRoles([role.id], user.id);
    const permissionCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USER_ROLES};`
    );
    expect(permissionCount.length).toBe(1);
    expect(permissionCount).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  it("Should get user's roles", async () => {
    const user = await insertAuthUser();
    const role = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([role.id], user.id);
    const roles = await auth.getAuthUserRoles(user.id);

    expect(roles.data?.length).toBe(1);
    expect(roles).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([
          expect.objectContaining({
            name: role.name
          })
        ])
      })
    );
  });

  it("Should revoke user's roles and ignore those he doesn't have", async () => {
    const user = await insertAuthUser();
    const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 3, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const auth = Auth.getInstance();
    await auth.grantRoles([role1.id], user.id);

    const roles = await auth.getAuthUserRoles(user.id);
    expect(roles.data?.length).toBe(1);

    await auth.revokeRoles([role1.name, role2.name], user.id);
    const roles2 = await auth.getAuthUserRoles(user.id);
    expect(roles2.data.length).toBe(0);
  });

  it("Should revoke user's roles and leave the ones not being removed", async () => {
    const user = await insertAuthUser();
    const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 4, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const role3 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 5, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const auth = Auth.getInstance();
    await auth.grantRoles([role1.id, role3.id], user.id);

    const roles = await auth.getAuthUserRoles(user.id);

    expect(roles.data?.length).toBe(2);

    await auth.revokeRoles([role1.name, role2.name], user.id);

    const roles2 = await auth.getAuthUserRoles(user.id);

    expect(roles2.data.length).toBe(1);
    expect(roles2).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([
          expect.objectContaining({
            name: role3.name
          })
        ])
      })
    );
  });

  it('Should get user permissions', async () => {
    const user = await insertAuthUser();
    const role = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 5, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 6, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    await insertRoleWithPermissions(faker.lorem.words(3), [
      { permission_id: 4, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);
    const auth = Auth.getInstance();
    await auth.grantRoles([role.id, role1.id], user.id);

    const permissions = await auth.getAuthUserPermissions(user.id);

    expect(permissions.data.length).toBe(2);
    expect(permissions).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([
          expect.objectContaining({ permission_id: 5, read: PermissionLevel.OWN }),
          expect.objectContaining({ permission_id: 1, read: PermissionLevel.OWN })
        ])
      })
    );
  });

  it('Generate JWT token with provided data - no user', async () => {
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const contents = jwt.decode(token.data);
    expect(contents).toEqual(expect.objectContaining(obj));

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokenEntry).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: token.data,
          status: DbModelStatus.ACTIVE,
          user_id: null,
          subject: AuthJwtTokenType.USER_SIGN_UP
        })
      ])
    );
  });

  it('Generate JWT token with provided data - user', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const contents = jwt.decode(token.data);
    expect(contents).toEqual(expect.objectContaining(obj));

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokenEntry).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: token.data,
          status: DbModelStatus.ACTIVE,
          user_id: user.id,
          subject: AuthJwtTokenType.USER_SIGN_UP
        })
      ])
    );
  });

  it('Invalidate JWT token', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const contents = jwt.decode(token.data);
    expect(contents).toEqual(expect.objectContaining(obj));
    await auth.invalidateToken(token.data);

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokenEntry).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          token: token.data,
          status: 9,
          user_id: user.id,
          subject: AuthJwtTokenType.USER_SIGN_UP
        })
      ])
    );
  });

  it('Validate JWT token - 1 (TRUE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );
    const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);

    expect(isValid.status).toBe(true);
    expect(isValid.data).toEqual(expect.objectContaining(obj));
  });

  it('Validate JWT token - 2 (FALSE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );

    const contents = jwt.decode(token.data);
    await auth.invalidateToken(token.data);

    const validation = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);
    expect(validation.status).toBe(false);
    expect(validation.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.INVALID_TOKEN]));
  });

  it('Validate JWT token - 3 (FALSE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const differentSecretToken = jwt.sign(obj, 'badsecret', {
      subject: AuthJwtTokenType.USER_SIGN_UP,
      expiresIn: '1d'
    });
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );

    const isValid = await auth.validateToken(differentSecretToken, AuthJwtTokenType.USER_SIGN_UP);
    expect(!!isValid.data).toBe(false);
  });

  it('Validate JWT token - 4 (FALSE)', async () => {
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const differentSecretToken = jwt.sign(obj, 'badsecret', {
      subject: AuthJwtTokenType.USER_SIGN_UP,
      expiresIn: '1d'
    });

    const isValid = await auth.validateToken(differentSecretToken, AuthJwtTokenType.USER_SIGN_UP);
    expect(!!isValid.data).toBe(false);
  });

  it('Validate JWT token - 5 (FALSE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const expired = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `UPDATE ${AuthDbTables.TOKENS}
      SET expiresAt = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
      WHERE token = @token;`,
      { token: token.data }
    );

    const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);
    expect(!!isValid.data).toBe(false);
  });

  it('Validate JWT token - 6 (FALSE)', async () => {
    const auth = Auth.getInstance();
    const isValid = await auth.validateToken('badtoken', AuthJwtTokenType.USER_SIGN_UP);
    expect(!!isValid.data).toBe(false);
  });

  it('Validate JWT token - 7 (TRUE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );
    const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id);

    expect(isValid.status).toBe(true);
    expect(isValid.data).toEqual(expect.objectContaining(obj));
  });

  it('Validate JWT token - 8 (FALSE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );
    const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id);

    expect(isValid.status).toBe(false);
  });

  it('Validate JWT token - 9 (FALSE)', async () => {
    const user = await insertAuthUser();
    const auth = Auth.getInstance();
    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT * FROM ${AuthDbTables.TOKENS};`
    );
    const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id + 1);

    expect(isValid.status).toBe(false);
  });

  // TODO/FIXME: should refreshing a token invalidate the old one?
  it('Return new token with same data', async () => {
    const auth = Auth.getInstance();

    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, null);
    const newToken = await auth.refreshToken(token.data);
    const contents = jwt.decode(token.data);
    expect(contents).toEqual(
      expect.objectContaining({
        ...obj
      })
    );
    const isValid = await auth.validateToken(newToken.data, AuthJwtTokenType.USER_SIGN_UP);

    expect(!!isValid.data).toBe(true);
    expect(isValid).toEqual(
      expect.objectContaining({
        data: expect.objectContaining({
          ...obj
        })
      })
    );
  });

  it('Should not refresh invalid token', async () => {
    const auth = Auth.getInstance();

    const obj = {
      name: 'person',
      value: 42069,
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, null);
    await auth.invalidateToken(token.data);
    const newToken = await auth.refreshToken(token.data);
    expect(newToken.status).toBe(false);
    expect(newToken.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.INVALID_TOKEN]));
  });

  it('Add new role', async () => {
    const auth = Auth.getInstance();
    const roleStrOne = faker.lorem.words(3);
    const role1 = await auth.createRole(roleStrOne);
    expect(role1.status).toBe(true);
    expect(role1.data).toEqual(
      expect.objectContaining({
        name: roleStrOne
      })
    );

    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  it('Add more than one new role with different names', async () => {
    const auth = Auth.getInstance();
    const roleStrOne = faker.lorem.words(3);
    const role1 = await auth.createRole(roleStrOne);
    expect(role1.status).toBe(true);
    expect(role1.data).toEqual(
      expect.objectContaining({
        name: roleStrOne
      })
    );
    const roleStrTwo = faker.lorem.words(3);
    const role2 = await auth.createRole(roleStrTwo);
    expect(role2.status).toBe(true);
    expect(role2.data).toEqual(
      expect.objectContaining({
        name: roleStrTwo
      })
    );

    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 2
        })
      ])
    );
  });

  it('Add roles with same name', async () => {
    const auth = Auth.getInstance();
    const roleStrOne = faker.lorem.words(3);
    const role1 = await auth.createRole(roleStrOne);
    expect(role1.status).toBe(true);
    expect(role1.data).toEqual(
      expect.objectContaining({
        name: roleStrOne
      })
    );
    const role2 = await auth.createRole(roleStrOne);
    expect(role2.status).toBe(false);
    expect(role2.errors).toEqual(expect.arrayContaining([AuthSystemErrorCode.SQL_SYSTEM_ERROR]));

    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  it('Create role', async () => {
    const auth = Auth.getInstance();

    const success = await auth.createRole('New role');

    expect(success.status).toBe(true);
    expect(success.data).toEqual(
      expect.objectContaining({
        name: 'New role'
      })
    );

    const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  it('Create role with same name (should fail)', async () => {
    const auth = Auth.getInstance();

    const success = await auth.createRole('New role');
    const failure = await auth.createRole('New role');

    expect(success.status).toBe(true);
    expect(success.data).toEqual(
      expect.objectContaining({
        name: 'New role'
      })
    );
    expect(failure.status).toBe(false);
    expect(failure.errors).toEqual(expect.arrayContaining([AuthSystemErrorCode.SQL_SYSTEM_ERROR]));

    const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  it('Delete role', async () => {
    const auth = Auth.getInstance();

    const success = await auth.createRole('New role');
    const failure = await auth.createRole('New role 2');
    await auth.deleteRole('New role');

    const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLES};`
    );

    expect(count.length).toBe(1);
    expect(count).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );
  });

  describe('Role permissions adding and removing tests', () => {
    const permissions = [
      {
        permission_id: 1,
        name: faker.lorem.words(1),
        read: PermissionLevel.OWN,
        write: PermissionLevel.NONE,
        execute: PermissionLevel.NONE
      },
      {
        permission_id: 2,
        name: faker.lorem.words(1),
        read: PermissionLevel.OWN,
        write: PermissionLevel.NONE,
        execute: PermissionLevel.NONE
      }
    ];

    it('Should add new permissions to role', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole('MyRole')).data;
      const success = await auth.addPermissionsToRole(role.id, permissions);
      const createdPermissions = success.data.rolePermissions.map((p) => ({
        permission_id: p.permission_id,
        name: p.name,
        read: p.read,
        write: p.write,
        execute: p.execute
      }));
      expect(success.status).toBe(true);
      expect(createdPermissions).toEqual(expect.arrayContaining(permissions));

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count.length).toBe(1);
      expect(count).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: permissions.length
          })
        ])
      );
    });

    it('Should not add permissions to non existing role', async () => {
      const auth = Auth.getInstance();
      const failure = await auth.addPermissionsToRole(123, permissions);
      expect(failure.status).toBe(false);
      expect(failure.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count.length).toBe(1);
      expect(count).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );
    });

    it('Should not add existing permissions to role permissions', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole('MyRole')).data;
      await auth.addPermissionsToRole(role.id, permissions);

      const failure = await auth.addPermissionsToRole(role.id, [
        {
          permission_id: 3,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        },
        ...permissions
      ]);
      expect(failure.status).toBe(false);
      expect(failure.errors).toEqual(expect.arrayContaining([AuthBadRequestErrorCode.ROLE_PERMISSION_ALREADY_EXISTS]));

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count.length).toBe(1);
      expect(count).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: permissions.length
          })
        ])
      );
    });

    it('Should remove permissions from role', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole('MyRole')).data;
      await auth.addPermissionsToRole(role.id, [
        ...permissions,
        {
          permission_id: 3,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        },
        {
          permission_id: 4,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count.length).toBe(1);
      expect(count).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 4
          })
        ])
      );

      const successRm = await auth.removePermissionsFromRole(role.id, [permissions[0].permission_id, permissions[1].permission_id]);
      expect(successRm.status).toBe(true);
      expect(successRm.data.rolePermissions.length).toBe(2);

      const count2 = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count2.length).toBe(1);
      expect(count2).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 2
          })
        ])
      );
    });

    it('Should not remove permissions from non existing role', async () => {
      const auth = Auth.getInstance();
      const failure = await auth.removePermissionsFromRole(123, [permissions[0].permission_id]);
      expect(failure.status).toBe(false);
      expect(failure.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));
    });

    it('Should not remove non existing permission from existing role', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole('MyRole5')).data;
      await auth.addPermissionsToRole(role.id, permissions);

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.ROLE_PERMISSIONS};`
      );

      expect(count.length).toBe(1);
      expect(count).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 2
          })
        ])
      );

      const failure = await auth.removePermissionsFromRole(role.id, [7]);
      expect(failure.status).toBe(false);
      expect(failure.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_PERMISSION_DOES_NOT_EXISTS]));
    });
  });

  describe('Create auth user tests', () => {
    it('Should create auth user', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(true);
      expect(user.data).toEqual(expect.objectContaining(obj));
    });

    it('Should create auth user - with PIN', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };
      const user = await auth.createAuthUser(obj);
      delete obj.PIN;

      expect(user.status).toBe(true);
      expect(user.data).toEqual(expect.objectContaining(obj));
    });

    it('Should not create two auth users with same PIN', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };
      const user = await auth.createAuthUser(obj);

      expect(user.status).toBe(true);
      expect(user.data).toEqual(expect.objectContaining(obj));

      obj.id = faker.datatype.number(10_000_000);
      const user1 = await auth.createAuthUser(obj);
      expect(user1.status).toBe(false);
      delete obj.PIN;
    });

    it('Should not create auth user with missing email', async () => {
      const auth = Auth.getInstance();

      const obj: any = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(true);
      expect(user.data).toEqual(expect.objectContaining(obj));
    });

    it('Should not create auth user with missing username', async () => {
      const auth = Auth.getInstance();

      const obj: any = {
        id: faker.datatype.number(10_000_000),
        email: faker.internet.email(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(false);
      expect(user.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT]));
    });

    it('Should not create auth user with bad username', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.email(),
        email: faker.internet.email(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(false);
      expect(user.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_NOT_VALID]));
    });

    it('Should not create auth user with missing password', async () => {
      const auth = Auth.getInstance();

      const obj: any = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`
      };
      const res = await auth.createAuthUser(obj);

      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PASSWORD_OR_PIN_NOT_PRESENT]));
    });
  });

  it('Delete user', async () => {
    const auth = Auth.getInstance();

    const obj = {
      id: faker.datatype.number(10_000_000),
      username: faker.internet.userName(),
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
      password: faker.internet.password()
    };
    const user = await auth.createAuthUser(obj);
    const success = await auth.deleteAuthUser(user.data.id);
    delete obj.password;

    expect(success.data).toEqual(expect.objectContaining(obj));
    expect(success.data.status).toBe(DbModelStatus.DELETED);

    const noAuthUser = await auth.getAuthUserById(user.data.id);
    expect(noAuthUser.status).toEqual(false);
    expect(noAuthUser.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
  });

  it('Login Email - OK', async () => {
    const auth = Auth.getInstance();

    const obj = {
      id: faker.datatype.number(10_000_000),
      username: faker.internet.userName(),
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
      password: faker.internet.password()
    };
    const user = await auth.createAuthUser(obj);
    const token = await auth.loginEmail(obj.email, obj.password);
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 1
        })
      ])
    );

    const contents = jwt.decode(token.data);
    expect(contents).toEqual(
      expect.objectContaining({
        userId: user.data.id,
        sub: AuthJwtTokenType.USER_AUTHENTICATION
      })
    );
  });

  it('Login Email - Bad password', async () => {
    const auth = Auth.getInstance();

    const obj = {
      id: faker.datatype.number(10_000_000),
      username: faker.internet.userName(),
      email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
      password: faker.internet.password()
    };
    const user = await auth.createAuthUser(obj);
    const token = await auth.loginEmail(obj.email, 'badpassword');
    const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
      `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
    );

    expect(tokens.length).toBe(1);
    expect(tokens).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          COUNT: 0
        })
      ])
    );

    expect(token.status).toEqual(false);
    expect(token.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]));
  });

  it('Query should join permission actions', async () => {
    const user = await insertAuthUser();

    const roleOne = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const roleTwo = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.ALL, write: PermissionLevel.NONE, execute: PermissionLevel.OWN },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.NONE, write: PermissionLevel.OWN, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([roleOne.id, roleTwo.id], user.id);

    const permissions = await auth.getAuthUserPermissions(user.id);

    expect(permissions.data.length).toBe(2);
    expect(permissions).toEqual(
      expect.objectContaining({
        data: expect.arrayContaining([
          expect.objectContaining({ permission_id: 1, read: 2, write: 0, execute: 1 }),
          expect.objectContaining({ permission_id: 2, read: PermissionLevel.OWN, write: 1, execute: 0 })
        ])
      })
    );
  });
  it('Check if user can access - OK 1', async () => {
    const user = await insertAuthUser();

    const roleOne = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const roleTwo = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.ALL, write: PermissionLevel.NONE, execute: PermissionLevel.OWN },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.NONE, write: PermissionLevel.OWN, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([roleOne.id, roleTwo.id], user.id);

    const canAccess = await auth.canAccess(user.id, [
      {
        permission: 1,
        type: PermissionType.EXECUTE,
        level: PermissionLevel.OWN
      },
      {
        permission: 2,
        type: PermissionType.READ,
        level: PermissionLevel.OWN
      },
      {
        permission: 2,
        type: PermissionType.WRITE,
        level: PermissionLevel.OWN
      }
    ]);

    expect(canAccess.data).toBe(true);
  });

  it('Check if user can access - OK 2', async () => {
    const user = await insertAuthUser();

    const roleOne = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.ALL, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const roleTwo = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.ALL },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.NONE, write: PermissionLevel.OWN, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([roleOne.id, roleTwo.id], user.id);

    const canAccess = await auth.canAccess(user.id, [
      {
        permission: 1,
        type: PermissionType.EXECUTE,
        level: PermissionLevel.OWN
      },
      {
        permission: 2,
        type: PermissionType.READ,
        level: PermissionLevel.OWN
      },
      {
        permission: 2,
        type: PermissionType.WRITE,
        level: PermissionLevel.OWN
      }
    ]);

    expect(canAccess.data).toBe(true);
  });

  it('Check if user can access - OK 3', async () => {
    const user = await insertAuthUser();

    const roleOne = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.ALL, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const roleTwo = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.ALL },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.NONE, write: PermissionLevel.OWN, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([roleOne.id, roleTwo.id], user.id);

    const canAccess = await auth.canAccess(user.id, [
      {
        permission: 1,
        type: PermissionType.READ,
        level: PermissionLevel.ALL
      },
      {
        permission: 1,
        type: PermissionType.EXECUTE,
        level: PermissionLevel.ALL
      }
    ]);

    expect(canAccess.data).toBe(true);
  });

  it('Check if user can access - NOK', async () => {
    const user = await insertAuthUser();

    const roleOne = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.ALL, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const roleTwo = await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.ALL },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.NONE, write: PermissionLevel.OWN, execute: PermissionLevel.NONE }
    ]);

    const auth = Auth.getInstance();
    await auth.grantRoles([roleOne.id, roleTwo.id], user.id);

    const canAccess = await auth.canAccess(user.id, [
      {
        permission: 1,
        type: PermissionType.EXECUTE,
        level: PermissionLevel.OWN
      }
    ]);

    expect(canAccess.data).toBe(true);
  });

  describe('Login user with password and username/email', () => {
    it('Should login user with its email and password', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginEmail(obj.email, obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 1
          })
        ])
      );

      const contents = jwt.decode(token.data);
      expect(contents).toEqual(
        expect.objectContaining({
          userId: user.data.id,
          sub: AuthJwtTokenType.USER_AUTHENTICATION
        })
      );
    });

    it('Should not login user with its email and incorrect password', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginEmail(obj.email, 'badpassword');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );

      expect(token.status).toEqual(false);
      expect(token.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]));
    });

    it('Should login user with its username and password', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };

      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername(obj.username, obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 1
          })
        ])
      );

      const contents = jwt.decode(token.data);
      expect(contents).toEqual(
        expect.objectContaining({
          userId: user.data.id,
          sub: AuthJwtTokenType.USER_AUTHENTICATION
        })
      );
    });

    it('Should not login user with its username and incorrect password', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername(obj.username, 'bad_password');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );

      expect(token.status).toEqual(false);
      expect(token.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]));
    });

    it('Should not login non existing user', async () => {
      const auth = Auth.getInstance();

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername('wrong_username', obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );

      expect(token.status).toEqual(false);
      expect(token.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });
  });

  describe("Change user's username and email tests", () => {
    it("Should change user's username", async () => {
      const auth = Auth.getInstance();
      const newUsername = 'new_username';

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = (await auth.createAuthUser(obj)).data;

      const updatedRes = await auth.changeUsername(user.id, newUsername);
      const updatedUser = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT * FROM \`${AuthDbTables.USERS}\`
       WHERE username = @newUsername
      `,
        {
          newUsername
        }
      );

      expect(updatedRes.status).toEqual(true);
      expect(updatedRes.data.username).toEqual(newUsername);
      expect(updatedUser.length).toBe(1);
    });

    it("Should not change user's username that is already taken", async () => {
      const auth = Auth.getInstance();

      const existingUser = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password()
        })
      ).data;

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password()
        })
      ).data;

      const updatedRes = await auth.changeUsername(user.id, existingUser.username);
      expect(updatedRes.status).toEqual(false);
      expect(updatedRes.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN]));
    });

    it("Should change user's email", async () => {
      const auth = Auth.getInstance();
      const newEmail = `${Math.floor(Math.random() * 10_000)}@domain-example.com`;

      const obj = {
        id: faker.datatype.number(10_000_000),
        username: faker.internet.userName(),
        email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
        password: faker.internet.password()
      };
      const user = (await auth.createAuthUser(obj)).data;

      const updatedRes = await auth.changeEmail(user.id, newEmail);
      const updatedUser = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT * FROM \`${AuthDbTables.USERS}\`
       WHERE email = @newEmail
      `,
        {
          newEmail
        }
      );

      expect(updatedRes.status).toEqual(true);
      expect(updatedRes.data.email).toEqual(newEmail);
      expect(updatedUser.length).toBe(1);
    });

    it("Should not change user's email that is already taken", async () => {
      const auth = Auth.getInstance();

      const existingUser = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password()
        })
      ).data;

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password()
        })
      ).data;

      const updatedRes = await auth.changeEmail(user.id, existingUser.email);
      expect(updatedRes.status).toEqual(false);
      expect(updatedRes.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN]));
    });
  });

  describe("Change user's password tests", () => {
    it("Should change user's password if the correct current password is provided", async () => {
      const auth = Auth.getInstance();
      const currentPassword = faker.internet.password();
      const newPassword = faker.internet.password();

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: currentPassword
        })
      ).data;

      const updatedRes = await auth.changePassword(user.id, currentPassword, newPassword);
      expect(updatedRes.status).toEqual(true);
      expect(await updatedRes.data.comparePassword(newPassword)).toEqual(true);
    });

    it("Should not change user's password if the incorrect current password is provided", async () => {
      const auth = Auth.getInstance();
      const currentPassword = faker.internet.password();
      const newPassword = faker.internet.password();

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: currentPassword
        })
      ).data;

      const updatedRes = await auth.changePassword(user.id, 'incorrect_password', newPassword);
      expect(updatedRes.status).toEqual(false);
      expect(updatedRes.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]));
    });

    it("Should change user's password if the incorrect current password is provided, but force parameter is set on TRUE", async () => {
      const auth = Auth.getInstance();
      const currentPassword = faker.internet.password();
      const newPassword = faker.internet.password();

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: currentPassword
        })
      ).data;

      const updatedRes = await auth.changePassword(user.id, 'incorrect_password', newPassword, true);
      expect(updatedRes.status).toEqual(true);
      expect(await updatedRes.data.comparePassword(newPassword)).toEqual(true);
    });
  });

  describe('Login with PIN tests', () => {
    it('Should login user with its PIN', async () => {
      const auth = Auth.getInstance();

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password(),
          PIN: '1234'
        })
      ).data;

      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      await auth.grantRoles([role.id], user.id);

      const token = await auth.loginPin(user.PIN);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 1
          })
        ])
      );

      const contents = jwt.decode(token.data);
      expect(contents).toEqual(
        expect.objectContaining({
          userId: user.id,
          sub: AuthJwtTokenType.USER_AUTHENTICATION
        })
      );
    });

    it('Should not login user with its incorrect PIN', async () => {
      const auth = Auth.getInstance();

      const user = (
        await auth.createAuthUser({
          id: faker.datatype.number(10_000_000),
          username: faker.internet.userName(),
          email: `${Math.floor(Math.random() * 10_000)}@domain-example.com`,
          password: faker.internet.password(),
          PIN: '1234'
        })
      ).data;

      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      await auth.grantRoles([role.id], user.id);

      const token = await auth.loginPin('2345');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramQuery(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokens.length).toBe(1);
      expect(tokens).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );

      expect(token.status).toEqual(false);
      expect(token.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.USER_NOT_AUTHENTICATED]));
    });
  });
});
