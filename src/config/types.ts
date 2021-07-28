/* eslint-disable no-shadow */

export enum AuthDbTables {
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

/**
 * Validator Error codes - 422000.
 */
export enum AuthValidatorErrorCode {
  DEFAULT_VALIDATION_ERROR = 422000,
  USER_EMAIL_NOT_PRESENT = 422003,
  USER_EMAIL_NOT_VALID = 422004,
  USER_EMAIL_ALREADY_TAKEN = 422005,
  USER_PASSWORD_NOT_PRESENT = 422006,
  USER_PASSWORD_NOT_VALID = 422007,
  USER_ID_NOT_PRESENT = 422012,
  USER_ID_ALREADY_TAKEN = 422013,
  USER_USERNAME_NOT_PRESENT = 422014,
  USER_USERNAME_NOT_VALID = 422015,
  USER_USERNAME_ALREADY_TAKEN = 422016,
  ROLE_ID_NOT_PRESENT = 422017,
  PERMISSION_NOT_PRESENT = 422018,
  READ_PERMISSION_LEVEL_NOT_SET = 422019,
  WRITE_PERMISSION_LEVEL_NOT_SET = 422020,
  EXECUTE_PERMISSION_LEVEL_NOT_SET = 422021,
  ROLE_NAME_NOT_PRESENT = 422022,
}

/**
 * Bad request error codes - 400000.
 */
export enum AuthBadRequestErrorCode {
  DEFAULT_BAD_REQUEST_ERROR = 400000,
  DEFAULT_SQL_ERROR = 400001,
  MISSING_DATA_ERROR = 400002,
}


/**
 * Authentication error codes - 401000.
 */
export enum AuthAuthenticationErrorCode {
  MISSING_AUTHENTICATION_TOKEN = 401001,
  INVALID_AUTHENTICATION_TOKEN = 401002,
  USER_NOT_AUTHENTICATED = 401003
}

export enum AuthJwtTokenType {
  USER_AUTHENTICATION = 'USER_AUTHENTICATION',
  USER_SIGN_UP = 'USER_SIGN_UP',
}

