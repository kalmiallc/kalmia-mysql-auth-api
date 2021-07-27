/* eslint-disable no-shadow */

export enum DbTables {
  USERS = 'auth_user',
  TOKENS = 'auth_token',
  ROLES = 'auth_role',
  USER_ROLES = 'auth_user_role',
  ROLE_PERMISSIONS = 'auth_role_permission',
}

export enum PermissionType {
  READ = 'read',
  WRITE = 'write',
  EXECUTE = 'execute'
}

export enum PermissionLevel {
  NONE = 0,
  OWN = 1,
  ALL = 2
}
