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
  USER_PASSWORD_OR_PIN_NOT_PRESENT = 422006,
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
  USER_PIN_NOT_CORRECT_LENGTH = 422023,
  USER_PIN_ALREADY_TAKEN = 422024,
}

/**
 * Bad request error codes - 400000.
 */
export enum AuthBadRequestErrorCode {
  DEFAULT_BAD_REQUEST_ERROR = 400000,
  MISSING_DATA_ERROR = 400001,
}

/**
 * System error codes - 500000.
 */
export enum AuthSystemErrorCode {
  DEFAULT_SYSTEM_ERROR = 500000,
  UNHANDLED_SYSTEM_ERROR = 500001,
  SQL_SYSTEM_ERROR = 500002
}

/**
 * Resource not found error codes - 404000.
 */
export enum AuthResourceNotFoundErrorCode {
  DEFAULT_RESOURCE_NOT_FOUND_ERROR = 404000,
  AUTH_USER_DOES_NOT_EXISTS = 404001
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
