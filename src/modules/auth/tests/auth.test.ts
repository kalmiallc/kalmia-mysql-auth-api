import { createHash } from 'crypto';
import * as faker from 'faker';
import * as jwt from 'jsonwebtoken';
import { DbModelStatus, MySqlConnManager, MySqlUtil } from 'kalmia-sql-lib';
import { Pool } from 'mysql2/promise';
import { AuthUser } from '../../..';
import { env } from '../../../config/env';
import {
  AuthAuthenticationErrorCode,
  AuthBadRequestErrorCode,
  AuthDbTables,
  AuthJwtTokenType,
  AuthResourceNotFoundErrorCode,
  AuthValidatorErrorCode,
  PermissionLevel,
  PermissionType
} from '../../../config/types';
import { RolePermission } from '../../auth-user/models/role-permission.model';
import { Role } from '../../auth-user/models/role.model';
import { insertRoleWithPermissions } from '../../test-helpers/permission';
import { cleanDatabase, closeConnectionToDb, connectToDb } from '../../test-helpers/setup';
import { insertAuthUser } from '../../test-helpers/test-user';
import { Auth } from '../auth';

describe('Auth service tests', () => {
  beforeEach(async () => {
    await connectToDb();
  });

  afterEach(async () => {
    await cleanDatabase();
  });

  afterAll(async () => {
    await closeConnectionToDb();
  });

  describe('Get auth user tests - ID, email, username, PIN', () => {
    it('Should get user by his ID', async () => {
      const auth = Auth.getInstance();
      const user = await insertAuthUser();

      const userRes = await auth.getAuthUserById(user.id);
      expect(userRes.data.exists()).toBe(true);
      expect(user.id).toBe(userRes?.data?.id);
      expect(user.email).toBe(userRes?.data?.email);
    });

    it('Should not get non existing user by its ID', async () => {
      const auth = Auth.getInstance();

      const userRes = await auth.getAuthUserById(123);
      expect(userRes.status).toEqual(false);
      expect(userRes.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });

    it('Should get user by its email', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();

      const userRes = await auth.getAuthUserByEmail(user.email);
      expect(userRes.data.exists()).toBe(true);
      expect(user.id).toBe(userRes?.data?.id);
      expect(user.email).toBe(userRes?.data?.email);
    });

    it('Should not get non existing user by its email', async () => {
      const auth = Auth.getInstance();

      const userRes = await auth.getAuthUserByEmail('non.existent@example.com');
      expect(userRes.status).toEqual(false);
      expect(userRes.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });
  });

  describe('Delete user test', () => {
    it('Should delete existing user', async () => {
      const auth = Auth.getInstance();

      const obj = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const deletedUser = await auth.deleteAuthUser(user?.data?.id);
      delete obj?.password;

      expect(deletedUser.data).toEqual(expect.objectContaining(obj));
      expect(deletedUser?.data.status).toBe(DbModelStatus.DELETED);

      const noAuthUser = await auth.getAuthUserById(user?.data?.id);
      expect(noAuthUser.status).toEqual(false);
      expect(noAuthUser.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });

    it('Should not delete non-existing user', async () => {
      const auth = Auth.getInstance();

      const res = await auth.deleteAuthUser(123);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });
  });

  it('[HELPER] Query should create and find 1 role with 2 permissions', async () => {
    await insertRoleWithPermissions(faker.address.city(), [
      { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE },
      { permission_id: 2, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
    ]);

    const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

    const permissionCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

  describe("Grant user's roles tests", () => {
    it('Should grant role to user', async () => {
      const auth = Auth.getInstance();

      let user = await insertAuthUser();
      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      const res = await auth.grantRoles([role.id], user.id);
      expect(res.status).toBe(true);

      user = res.data;
      expect(user.roles.length).toBe(1);
      expect(user.permissions.length).toBe(1);

      const updatedUser = await new AuthUser().populateById(user.id);
      await updatedUser.populateRoles();
      expect(updatedUser.roles.length).toBe(1);
      expect(updatedUser.permissions.length).toBe(1);

      const rolesCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USER_ROLES};`
      );
      expect(rolesCount.length).toBe(1);
      expect(rolesCount).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 1
          })
        ])
      );
    });

    it('Should grant many roles to user', async () => {
      const auth = Auth.getInstance();

      let user = await insertAuthUser();
      const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      const role3 = await insertRoleWithPermissions(faker.lorem.words(3), [
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
      ]);
      const res = await auth.grantRoles([role1.id, role2.id, role3.id], user.id);
      expect(res.status).toBe(true);

      user = res.data;
      expect(user.roles.length).toBe(3);
      expect(user.permissions.length).toBe(4);

      const updatedUser = await new AuthUser().populateById(user.id);
      await updatedUser.populateRoles();
      expect(updatedUser.roles.length).toBe(3);
      expect(updatedUser.permissions.length).toBe(4);

      const permissionCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USER_ROLES};`
      );
      expect(permissionCount.length).toBe(1);
      expect(permissionCount).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 3
          })
        ])
      );
    });

    it('Should not grant non-existing role to user', async () => {
      const auth = Auth.getInstance();
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
      const res = await auth.grantRoles([123, role.id], user.id);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));

      const permissionCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USER_ROLES};`
      );
      expect(permissionCount.length).toBe(1);
      expect(permissionCount).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 0
          })
        ])
      );
    });

    it('Should not grant role to non-existing user', async () => {
      const auth = Auth.getInstance();
      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      const res = await auth.grantRoles([role.id], 123);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });

    it('Should not grant already existing role to user', async () => {
      const auth = Auth.getInstance();

      let user = await insertAuthUser();
      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      let res = await auth.grantRoles([role.id], user.id);
      expect(res.status).toBe(true);

      res = await auth.grantRoles([role.id], user.id);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthBadRequestErrorCode.AUTH_USER_ROLE_ALREADY_EXISTS]));

      const rolesCount = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'COUNT' FROM ${AuthDbTables.USER_ROLES};`
      );
      expect(rolesCount.length).toBe(1);
      expect(rolesCount).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            COUNT: 1
          })
        ])
      );
    });
  });

  describe("Get user's roles tests", () => {
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

    it('Should not get roles of non-existing user', async () => {
      const auth = Auth.getInstance();

      const res = await auth.getAuthUserRoles(123);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });
  });

  describe("Revoke user's roles tests", () => {
    it("Should revoke many user's roles", async () => {
      const user = await insertAuthUser();
      const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 3, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const auth = Auth.getInstance();
      await auth.grantRoles([role1.id, role2.id], user.id);

      const roles = await auth.getAuthUserRoles(user.id);
      expect(roles.data?.length).toBe(2);

      await auth.revokeRoles([role1.id, role2.id], user.id);
      const roles2 = await auth.getAuthUserRoles(user.id);
      expect(roles2.data.length).toBe(0);
    });

    it("Should revoke one of the user's roles", async () => {
      const user = await insertAuthUser();
      const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 3, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const auth = Auth.getInstance();
      await auth.grantRoles([role1.id, role2.id], user.id);

      const roles = await auth.getAuthUserRoles(user.id);
      expect(roles.data?.length).toBe(2);

      await auth.revokeRoles([role1.id], user.id);
      const roles2 = await auth.getAuthUserRoles(user.id);
      expect(roles2.data.length).toBe(1);
    });

    it("Should revoke one of the user's roles", async () => {
      const user = await insertAuthUser();
      const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const role2 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 3, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const auth = Auth.getInstance();
      await auth.grantRoles([role1.id, role2.id], user.id);

      const roles = await auth.getAuthUserRoles(user.id);
      expect(roles.data?.length).toBe(2);

      await auth.revokeRoles([role1.id], user.id);
      const roles2 = await auth.getAuthUserRoles(user.id);
      expect(roles2.data.length).toBe(1);
    });

    it('Should not revoke role from non-existing user', async () => {
      const auth = Auth.getInstance();
      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        {
          permission_id: 1,
          name: faker.lorem.words(1),
          read: PermissionLevel.OWN,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      const res = await auth.revokeRoles([role.id], 123);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.AUTH_USER_DOES_NOT_EXISTS]));
    });

    it("Should not revoke user's roles if nonexistent role is specified", async () => {
      const user = await insertAuthUser();
      const role1 = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      const auth = Auth.getInstance();
      await auth.grantRoles([role1.id], user.id);

      const roles = await auth.getAuthUserRoles(user.id);
      expect(roles.data?.length).toBe(1);

      const res = await auth.revokeRoles([role1.id, 123], user.id);
      expect(res.status).toEqual(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));

      const roles2 = await auth.getAuthUserRoles(user.id);
      expect(roles2.data.length).toBe(1);
    });

    it("Should not revoke user's roles if role that he does not have is specified", async () => {
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

      const res = await auth.revokeRoles([role1.id, role2.id], user.id);
      expect(res.status).toEqual(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthBadRequestErrorCode.AUTH_USER_ROLE_DOES_NOT_EXISTS]));

      const roles2 = await auth.getAuthUserRoles(user.id);
      expect(roles2.data.length).toBe(1);
    });
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

  describe('Generate JWT token tests', () => {
    it('Should generate new JWT token and create new row in database with provided data and no user data', async () => {
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokenEntry).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            token: createHash('sha256').update(token.data).digest('hex'),
            status: DbModelStatus.ACTIVE,
            user_id: null,
            subject: AuthJwtTokenType.USER_SIGN_UP
          })
        ])
      );
    });

    it('Should generate new JWT token and create new row in database with provided data and user data', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokenEntry).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            token: createHash('sha256').update(token.data).digest('hex'),
            status: DbModelStatus.ACTIVE,
            user_id: user.id,
            subject: AuthJwtTokenType.USER_SIGN_UP
          })
        ])
      );
    });
  });

  describe('Invalidate JWT token tests', () => {
    it('Should invalidate JWT token', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );

      expect(tokenEntry).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            token: createHash('sha256').update(token.data).digest('hex'),
            status: 9,
            user_id: user.id,
            subject: AuthJwtTokenType.USER_SIGN_UP
          })
        ])
      );
    });
  });

  describe('Validate JWT token tests', () => {
    it('Should validate JWT token - Should succeed', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );
      const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);

      expect(isValid.status).toBe(true);
      expect(isValid.data).toEqual(expect.objectContaining(obj));
    });

    it('Validate JWT token - Should fail due to token being invalidated', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );

      const contents = jwt.decode(token.data);
      await auth.invalidateToken(token.data);

      const validation = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);
      expect(validation.status).toBe(false);
      expect(validation.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.INVALID_TOKEN]));
    });

    it('Validate JWT token - Should fail due to mis-matched JWT encoding secret', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const differentSecretToken = jwt.sign(obj, 'badsecret', {
        subject: AuthJwtTokenType.USER_SIGN_UP,
        expiresIn: '1d'
      });
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const isValid = await auth.validateToken(differentSecretToken, AuthJwtTokenType.USER_SIGN_UP);
      expect(!!isValid.data).toBe(false);
    });

    it('Validate JWT token - Should fail due to token not being present in database', async () => {
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const differentSecretToken = jwt.sign(obj, env.APP_SECRET, {
        subject: AuthJwtTokenType.USER_SIGN_UP,
        expiresIn: '1d'
      });

      const isValid = await auth.validateToken(differentSecretToken, AuthJwtTokenType.USER_SIGN_UP);
      expect(!!isValid.data).toBe(false);
    });

    it('Validate JWT token - Should fail due to token expiring according to database time', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const expired = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `UPDATE ${AuthDbTables.TOKENS}
      SET expiresAt = DATE_SUB(CURDATE(), INTERVAL 1 DAY)
      WHERE token = @token;`,
        { token: createHash('sha256').update(token.data).digest('hex') }
      );

      const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP);
      expect(!!isValid.data).toBe(false);
    });

    it('Validate JWT token - Should fail due to bad token', async () => {
      const auth = Auth.getInstance();
      const isValid = await auth.validateToken('badtoken', AuthJwtTokenType.USER_SIGN_UP);
      expect(!!isValid.data).toBe(false);
    });

    it('Validate JWT token - Should succeed', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );
      const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id);

      expect(isValid.status).toBe(true);
      expect(isValid.data).toEqual(expect.objectContaining(obj));
    });

    it('Validate JWT token - Should fail due to missing userId', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );
      const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id);

      expect(isValid.status).toBe(false);
    });

    it('Validate JWT token -  Should fail due to mis-matched userId', async () => {
      const user = await insertAuthUser();
      const auth = Auth.getInstance();
      const obj = {
        name: 'person',
        value: 42069,
        email: faker.internet.email().toLowerCase()
      };

      const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, user.id);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const tokenEntry = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT * FROM ${AuthDbTables.TOKENS};`
      );
      const isValid = await auth.validateToken(token.data, AuthJwtTokenType.USER_SIGN_UP, user.id + 1);
      expect(isValid.status).toBe(false);
    });
  });

  // TODO/FIXME: should refreshing a token invalidate the old one?
  it('Return new token with same data', async () => {
    const auth = Auth.getInstance();

    const obj = {
      name: 'person',
      value: 42069,
      email: faker.internet.email().toLowerCase()
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
      email: faker.internet.email().toLowerCase()
    };

    const token = await auth.generateToken(obj, AuthJwtTokenType.USER_SIGN_UP, null);
    await auth.invalidateToken(token.data);
    const newToken = await auth.refreshToken(token.data);
    expect(newToken.status).toBe(false);
    expect(newToken.errors).toEqual(expect.arrayContaining([AuthAuthenticationErrorCode.INVALID_TOKEN]));
  });

  describe('Create new role tests', () => {
    it('Should create new role', async () => {
      const auth = Auth.getInstance();

      const roleName = faker.lorem.word();
      const role = await auth.createRole(roleName);
      expect(role.status).toBe(true);
      expect(role.data).toEqual(
        expect.objectContaining({
          name: roleName
        })
      );

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const createdRole = await new Role().populateById(role.data.id);
      expect(createdRole.exists()).toEqual(true);
    });

    it('Should not create new role with existing name', async () => {
      const auth = Auth.getInstance();

      const roleName = faker.lorem.word();
      const role = await auth.createRole(roleName);

      expect(role.status).toBe(true);
      expect(role.data).toEqual(
        expect.objectContaining({
          name: roleName
        })
      );

      const newRole = await auth.createRole(roleName);
      expect(newRole.status).toBe(false);
      expect(newRole.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_NAME_ALREADY_TAKEN]));

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

    it('Should add more than one new role with different names', async () => {
      const auth = Auth.getInstance();

      const roleName1 = faker.lorem.words(3);
      const role1 = await auth.createRole(roleName1);
      expect(role1.status).toBe(true);
      expect(role1.data).toEqual(
        expect.objectContaining({
          name: roleName1
        })
      );

      const roleName2 = faker.lorem.words(3);
      const role2 = await auth.createRole(roleName2);
      expect(role2.status).toBe(true);
      expect(role2.data).toEqual(
        expect.objectContaining({
          name: roleName2
        })
      );

      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
  });

  describe('Delete role tests', () => {
    it('Should delete role, role permissions and user roles', async () => {
      const auth = Auth.getInstance();
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
        },
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
      ];
      const role = (await auth.createRole(faker.lorem.words(1))).data;
      const role1 = (await auth.createRole(faker.lorem.words(1))).data;
      await auth.addPermissionsToRole(role.id, permissions);
      await auth.addPermissionsToRole(role1.id, [permissions[0], permissions[1]]);

      const user = (
        await auth.createAuthUser({
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;

      await auth.grantRoles([role.id, role1.id], user.id);
      await user.populateRoles();

      expect((await auth.getRolePermissions(role.id)).data.length).toEqual(4);
      expect((await new Role().getList({})).total).toEqual(2);
      expect(user.roles.length).toEqual(2);
      expect(user.permissions.length).toEqual(6);

      await auth.deleteRole(role.id);
      await user.populateRoles();

      expect((await new Role().getList({})).total).toEqual(1);
      expect(user.roles.length).toEqual(1);
      expect(user.permissions.length).toEqual(2);

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

    it('Should not delete non-existing role', async () => {
      const auth = Auth.getInstance();

      const res = await auth.deleteRole(123);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));
    });
  });

  describe('Role permissions adding tests', () => {
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

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

    it('Should not add role permission with missing data', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, [
        ...permissions,
        {
          permission_id: null,
          name: null,
          read: null,
          write: null,
          execute: null
        }
      ]);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_PERMISSION_ID_NOT_PRESENT]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_NAME_NOT_PRESENT]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_SET]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_SET]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET]));

      const notUpdatedRole = await new Role().populateById(role.id);
      expect(notUpdatedRole.rolePermissions.length).toBe(0);
    });

    it('Should not add role permission with invalid data', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, [
        ...permissions,
        {
          permission_id: 3,
          name: faker.lorem.word(),
          read: 123,
          write: 123,
          execute: 123
        }
      ]);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_VALID]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID]));

      const notUpdatedRole = await new Role().populateById(role.id);
      expect(notUpdatedRole.rolePermissions.length).toBe(0);
    });
  });

  describe('Role permissions removing tests', () => {
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

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const count2 = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const count = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

  describe('Role permissions updating tests', () => {
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

    it('Should update one role permission', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, permissions);
      expect(res.status).toBe(true);

      const permissionId = permissions[0].permission_id;
      res = await auth.updateRolePermissions(role.id, [
        {
          permission_id: permissionId,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        }
      ]);
      expect(res.status).toBe(true);
      let updatedPermission = res.data.rolePermissions.find((rp) => rp.permission_id === permissionId);
      expect(updatedPermission.read).toBe(PermissionLevel.ALL);
      expect(updatedPermission.write).toBe(PermissionLevel.ALL);
      expect(updatedPermission.execute).toBe(PermissionLevel.ALL);

      updatedPermission = await new RolePermission({}).populateByIds(role.id, permissionId);
      expect(updatedPermission.exists()).toBe(true);
      expect(updatedPermission.read).toBe(PermissionLevel.ALL);
      expect(updatedPermission.write).toBe(PermissionLevel.ALL);
      expect(updatedPermission.execute).toBe(PermissionLevel.ALL);
    });

    it('Should update many role permissions', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, [
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
      expect(res.status).toBe(true);

      res = await auth.updateRolePermissions(role.id, [
        {
          permission_id: permissions[0].permission_id,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        },
        {
          permission_id: permissions[1].permission_id,
          read: PermissionLevel.NONE,
          write: PermissionLevel.NONE,
          execute: PermissionLevel.NONE
        }
      ]);
      expect(res.status).toBe(true);
      let updatedPermission1 = res.data.rolePermissions.find((rp) => rp.permission_id === permissions[0].permission_id);
      expect(updatedPermission1.read).toBe(PermissionLevel.ALL);
      expect(updatedPermission1.write).toBe(PermissionLevel.ALL);
      expect(updatedPermission1.execute).toBe(PermissionLevel.ALL);

      updatedPermission1 = await new RolePermission({}).populateByIds(role.id, permissions[0].permission_id);
      expect(updatedPermission1.exists()).toBe(true);
      expect(updatedPermission1.read).toBe(PermissionLevel.ALL);
      expect(updatedPermission1.write).toBe(PermissionLevel.ALL);
      expect(updatedPermission1.execute).toBe(PermissionLevel.ALL);

      let updatedPermission2 = res.data.rolePermissions.find((rp) => rp.permission_id === permissions[1].permission_id);
      expect(updatedPermission2.read).toBe(PermissionLevel.NONE);
      expect(updatedPermission2.write).toBe(PermissionLevel.NONE);
      expect(updatedPermission2.execute).toBe(PermissionLevel.NONE);

      updatedPermission2 = await new RolePermission({}).populateByIds(role.id, permissions[1].permission_id);
      expect(updatedPermission2.exists()).toBe(true);
      expect(updatedPermission2.read).toBe(PermissionLevel.NONE);
      expect(updatedPermission2.write).toBe(PermissionLevel.NONE);
      expect(updatedPermission2.execute).toBe(PermissionLevel.NONE);
    });

    it('Should not update role permissions of non-existing role', async () => {
      const auth = Auth.getInstance();

      const res = await auth.addPermissionsToRole(123, permissions);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_DOES_NOT_EXISTS]));
    });

    it('Should not update non-existing role permission', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, permissions);
      expect(res.status).toBe(true);

      const permissionId = permissions[0].permission_id;
      res = await auth.updateRolePermissions(role.id, [
        {
          permission_id: permissionId,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        },
        {
          permission_id: 123,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        }
      ]);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthResourceNotFoundErrorCode.ROLE_PERMISSION_DOES_NOT_EXISTS]));

      const notUpdatedRole = await new Role().populateById(role.id);
      const notUpdatedPermission = notUpdatedRole.rolePermissions.find((rp) => rp.permission_id === permissionId);
      expect(notUpdatedPermission.read).toBe(permissions[0].read);
      expect(notUpdatedPermission.write).toBe(permissions[0].write);
      expect(notUpdatedPermission.execute).toBe(permissions[0].execute);
    });

    it('Should not update role permission with missing data', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, permissions);
      expect(res.status).toBe(true);

      res = await auth.updateRolePermissions(role.id, [
        {
          permission_id: permissions[0].permission_id,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        },
        {
          permission_id: permissions[1].permission_id,
          read: null,
          write: null,
          execute: null
        }
      ]);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_SET]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_SET]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET]));

      const notUpdatedRole = await new Role().populateById(role.id);
      const notUpdatedPermission = notUpdatedRole.rolePermissions.find((rp) => rp.permission_id === permissions[0].permission_id);
      expect(notUpdatedPermission.read).toBe(permissions[0].read);
      expect(notUpdatedPermission.write).toBe(permissions[0].write);
      expect(notUpdatedPermission.execute).toBe(permissions[0].execute);
    });

    it('Should not update role permission with invalid data', async () => {
      const auth = Auth.getInstance();
      const role = (await auth.createRole(faker.lorem.word())).data;
      let res = await auth.addPermissionsToRole(role.id, permissions);
      expect(res.status).toBe(true);

      res = await auth.updateRolePermissions(role.id, [
        {
          permission_id: permissions[0].permission_id,
          read: PermissionLevel.ALL,
          write: PermissionLevel.ALL,
          execute: PermissionLevel.ALL
        },
        {
          permission_id: permissions[1].permission_id,
          read: 123,
          write: 123,
          execute: 123
        }
      ]);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_READ_LEVEL_NOT_VALID]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID]));

      const notUpdatedRole = await new Role().populateById(role.id);
      const notUpdatedPermission = notUpdatedRole.rolePermissions.find((rp) => rp.permission_id === permissions[0].permission_id);
      expect(notUpdatedPermission.read).toBe(permissions[0].read);
      expect(notUpdatedPermission.write).toBe(permissions[0].write);
      expect(notUpdatedPermission.execute).toBe(permissions[0].execute);
    });
  });

  describe('Create auth user tests', () => {
    it('Should create new auth user', async () => {
      const auth = Auth.getInstance();

      const userData = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };

      const res = await auth.createAuthUser(userData);
      expect(res.status).toBe(true);

      const user = res.data;
      expect(user.id).toBeDefined();
      expect(user.username).toBe(userData.username);
      expect(user.email).toBe(userData.email);
      expect(user._createTime).not.toBeNull();
      expect(user._updateTime).not.toBeNull();

      const createdUser = await new AuthUser().populateById(user.id);
      expect(createdUser.exists()).toBe(true);
    });

    it('Should not create new auth user with missing data', async () => {
      const auth = Auth.getInstance();

      const res = await auth.createAuthUser({} as any);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PASSWORD_NOT_PRESENT]));
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT]));
    });

    it('Should create auth user - with PIN', async () => {
      const auth = Auth.getInstance();

      const userData = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password(),
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };

      const res = await auth.createAuthUser(userData);
      expect(res.status).toBe(true);

      const user = res.data;
      expect(user.id).toBeDefined();
      expect(user.username).toBe(userData.username);
      expect(user.email).toBe(userData.email);
      expect(user.PIN).toBe(userData.PIN);
      expect(user._createTime).not.toBeNull();
      expect(user._updateTime).not.toBeNull();

      const createdUser = await new AuthUser().populateById(user.id);
      expect(createdUser.PIN).toBe(userData.PIN);
      expect(createdUser.exists()).toBe(true);
    });

    it('Should not create two auth users with same PIN', async () => {
      const auth = Auth.getInstance();

      const userData1 = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password(),
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };
      const res1 = await auth.createAuthUser(userData1);
      expect(res1.status).toBe(true);

      const userData2 = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password(),
        PIN: userData1.PIN
      };

      const res2 = await auth.createAuthUser(userData2);
      expect(res2.status).toBe(false);
      expect(res2.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PIN_ALREADY_TAKEN]));
    });

    it('Should not create two auth users with the same username', async () => {
      const auth = Auth.getInstance();

      const userData1 = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const res1 = await auth.createAuthUser(userData1);
      expect(res1.status).toBe(true);

      const userData2 = {
        username: userData1.username,
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };

      const res2 = await auth.createAuthUser(userData2);
      expect(res2.status).toBe(false);
      expect(res2.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN]));
    });

    it('Should not create two auth users with the same email', async () => {
      const auth = Auth.getInstance();

      const userData1 = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const res1 = await auth.createAuthUser(userData1);
      expect(res1.status).toBe(true);

      const userData2 = {
        username: faker.internet.userName(),
        email: userData1.email,
        password: faker.internet.password()
      };

      const res2 = await auth.createAuthUser(userData2);
      expect(res2.status).toBe(false);
      expect(res2.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN]));
    });

    it('Should not create auth user with too short or too long PIN', async () => {
      const auth = Auth.getInstance();

      let userData = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password(),
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };
      let res = await auth.createAuthUser(userData);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PIN_NOT_CORRECT_LENGTH]));

      userData = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password(),
        PIN: `${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}${Math.floor(
          Math.random() * 10
        )}${Math.floor(Math.random() * 10)}${Math.floor(Math.random() * 10)}`
      };
      res = await auth.createAuthUser(userData);
      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PIN_NOT_CORRECT_LENGTH]));
    });

    it('Should not create auth user with missing email', async () => {
      const auth = Auth.getInstance();

      const obj: any = {
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
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(false);
      expect(user.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_NOT_PRESENT]));
    });

    // we don't do username validation -- username can be email.
    it.skip('Should not create auth user with invalid username', async () => {
      const auth = Auth.getInstance();

      const obj = {
        username: faker.internet.email().toLowerCase(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(false);
      expect(user.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_NOT_VALID]));
    });

    it('Should not create auth user with invalid email', async () => {
      const auth = Auth.getInstance();

      const obj = {
        username: faker.internet.userName(),
        email: faker.internet.userName(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      delete obj.password;

      expect(user.status).toBe(false);
      expect(user.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_EMAIL_NOT_VALID]));
    });

    it('Should not create auth user with missing password', async () => {
      const auth = Auth.getInstance();

      const obj: any = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase()
      };
      const res = await auth.createAuthUser(obj);

      expect(res.status).toBe(false);
      expect(res.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_PASSWORD_NOT_PRESENT]));
    });
  });

  describe('User access checking tests', () => {
    it('Check if user can access - Should succeed - Different roles fit all permission requirements 1', async () => {
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

    it('Check if user can access - Should succeed - Different roles fit all permission requirements 2', async () => {
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

    it('Check if user can access - Should succeed - Different roles fit all permission requirements 3', async () => {
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

    it('Check if user can access - Should fail due to insufficient permissions', async () => {
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
      await auth.grantRoles([roleOne.id], user.id);

      const canAccess = await auth.canAccess(user.id, [
        {
          permission: 1,
          type: PermissionType.EXECUTE,
          level: PermissionLevel.OWN
        }
      ]);

      expect(canAccess.data).toBe(false);

      await auth.grantRoles([roleTwo.id], user.id);
      const canAccess2 = await auth.canAccess(user.id, [
        {
          permission: 1,
          type: PermissionType.EXECUTE,
          level: PermissionLevel.ALL
        }
      ]);

      expect(canAccess2.data).toBe(true);
    });
  });

  describe('Login user with password and username/email tests', () => {
    it('Should login user with its email and password', async () => {
      const auth = Auth.getInstance();

      const obj = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginEmail(obj.email, obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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

      const user = (
        await auth.createAuthUser({
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;
      const token = await auth.loginEmail(user.email, 'badpassword');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };

      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername(obj.username, obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername(obj.username, 'bad_password');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = await auth.createAuthUser(obj);
      const token = await auth.loginUsername('wrong_username', obj.password);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = (await auth.createAuthUser(obj)).data;

      const updatedRes = await auth.changeUsername(user.id, newUsername);
      const updatedUser = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;

      const user = (
        await auth.createAuthUser({
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;

      const updatedRes = await auth.changeUsername(user.id, existingUser.username);
      expect(updatedRes.status).toEqual(false);
      expect(updatedRes.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_USERNAME_ALREADY_TAKEN]));
    });

    it("Should change user's email", async () => {
      const auth = Auth.getInstance();
      const newEmail = faker.internet.email().toLowerCase();

      const obj = {
        username: faker.internet.userName(),
        email: faker.internet.email().toLowerCase(),
        password: faker.internet.password()
      };
      const user = (await auth.createAuthUser(obj)).data;

      const updatedRes = await auth.changeEmail(user.id, newEmail);
      const updatedUser = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;

      const user = (
        await auth.createAuthUser({
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password()
        })
      ).data;

      const updatedRes = await auth.changeEmail(user.id, existingUser.email);
      expect(updatedRes.status).toEqual(false);
      expect(updatedRes.errors).toEqual(expect.arrayContaining([AuthValidatorErrorCode.USER_EMAIL_ALREADY_TAKEN]));
    });
  });

  describe("Change user's password tests", () => {
    it("Should change user's password if the correct current password is provided, also it should invalidate all user's auth tokens", async () => {
      const auth = Auth.getInstance();
      const currentPassword = faker.internet.password();
      const newPassword = faker.internet.password();
      const username = faker.internet.password();

      const user = (
        await auth.createAuthUser({
          username: username,
          email: faker.internet.email().toLowerCase(),
          password: currentPassword
        })
      ).data;

      await auth.loginUsername(username, currentPassword);
      await auth.loginUsername(username, currentPassword);
      await auth.loginUsername(username, currentPassword);
      await auth.loginUsername(username, currentPassword);
      await auth.loginUsername(username, currentPassword);

      let tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'count'
        FROM ${AuthDbTables.TOKENS} t
        WHERE t.user_id = ${user.id}
          AND t.status = ${DbModelStatus.ACTIVE};`
      );
      expect(tokens[0].count).toBe(5);

      const updatedRes = await auth.changePassword(user.id, currentPassword, newPassword);
      expect(updatedRes.status).toEqual(true);
      expect(await updatedRes.data.comparePassword(newPassword)).toEqual(true);

      tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'count'
        FROM ${AuthDbTables.TOKENS} t
        WHERE t.user_id = ${user.id}
          AND t.status = ${DbModelStatus.ACTIVE};`
      );
      expect(tokens[0].count).toBe(0);

      tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
        `SELECT COUNT(*) AS 'count'
        FROM ${AuthDbTables.TOKENS} t
        WHERE t.user_id = ${user.id}
          AND t.status = ${DbModelStatus.DELETED};`
      );
      expect(tokens[0].count).toBe(5);
    });

    it("Should not change user's password if the incorrect current password is provided", async () => {
      const auth = Auth.getInstance();
      const currentPassword = faker.internet.password();
      const newPassword = faker.internet.password();

      const user = (
        await auth.createAuthUser({
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
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
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
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
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password(),
          PIN: '1234'
        })
      ).data;

      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      await auth.grantRoles([role.id], user.id);

      const token = await auth.loginPin(user.PIN);
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
          username: faker.internet.userName(),
          email: faker.internet.email().toLowerCase(),
          password: faker.internet.password(),
          PIN: '1234'
        })
      ).data;

      const role = await insertRoleWithPermissions(faker.lorem.words(3), [
        { permission_id: 1, name: faker.lorem.words(1), read: PermissionLevel.OWN, write: PermissionLevel.NONE, execute: PermissionLevel.NONE }
      ]);
      await auth.grantRoles([role.id], user.id);

      const token = await auth.loginPin('2345');
      const tokens = await new MySqlUtil((await MySqlConnManager.getInstance().getConnection()) as Pool).paramExecute(
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
