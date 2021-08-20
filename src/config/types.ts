/* eslint-disable no-shadow */

/**
 * List of authentication service database tables.
 */
export enum AuthDbTables {
  USERS = 'authUser',
  TOKENS = 'authToken',
  ROLES = 'authRole',
  USER_ROLES = 'authUserRole',
  ROLE_PERMISSIONS = 'authRolePermission',
}

/**
 * Permission types definitions.
 */
export enum PermissionType {
  READ = 'read',
  WRITE = 'write',
  EXECUTE = 'execute'
}

/**
 * Permissions levels definitions.
 */
export enum PermissionLevel {
  NONE = 0,
  OWN = 1,
  ALL = 2
}

/**
 * Auth validator Error codes - 100_422000.
 */
export enum AuthValidatorErrorCode {
  DEFAULT_VALIDATION_ERROR = 100_422000,
  USER_EMAIL_NOT_PRESENT = 100_422001,
  USER_EMAIL_NOT_VALID = 100_422002,
  USER_EMAIL_ALREADY_TAKEN = 100_422003,
  USER_PASSWORD_OR_PIN_NOT_PRESENT = 100_422004,
  USER_PASSWORD_NOT_VALID = 100_422005,
  USER_ID_NOT_PRESENT = 100_422006,
  USER_ID_ALREADY_TAKEN = 100_422007,
  USER_USERNAME_NOT_PRESENT = 100_422008,
  USER_USERNAME_NOT_VALID = 100_422009,
  USER_USERNAME_ALREADY_TAKEN = 100_422010,
  ROLE_ID_NOT_PRESENT = 100_422011,
  PERMISSION_NOT_PRESENT = 100_422012,
  READ_PERMISSION_LEVEL_NOT_SET = 100_422013,
  WRITE_PERMISSION_LEVEL_NOT_SET = 100_422014,
  EXECUTE_PERMISSION_LEVEL_NOT_SET = 100_422015,
  ROLE_NAME_NOT_PRESENT = 100_422016,
  USER_PIN_NOT_CORRECT_LENGTH = 100_422017,
  USER_PIN_ALREADY_TAKEN = 100_422018,
}

/**
 * Bad request error codes - 100_400000.
 */
export enum AuthBadRequestErrorCode {
  DEFAULT_BAD_REQUEST_ERROR = 100_400000,
  MISSING_DATA_ERROR = 100_400001,
}

/**
 * System error codes - 500000.
 */
export enum AuthSystemErrorCode {
  DEFAULT_SYSTEM_ERROR = 100_500000,
  UNHANDLED_SYSTEM_ERROR = 100_500001,
  SQL_SYSTEM_ERROR = 100_500002
}

/**
 * Resource not found error codes - 404000.
 */
export enum AuthResourceNotFoundErrorCode {
  DEFAULT_RESOURCE_NOT_FOUND_ERROR = 100_404000,
  AUTH_USER_DOES_NOT_EXISTS = 100_404001,
  ROLE_DOES_NOT_EXISTS = 100_404002,
}

/**
 * Authentication error codes - 401000.
 */
export enum AuthAuthenticationErrorCode {
  MISSING_AUTHENTICATION_TOKEN = 100_401001,
  INVALID_TOKEN = 100_401002,
  USER_NOT_AUTHENTICATED = 100_401003
}

/**
 * Authentication JWT token types definitions.
 */
export enum AuthJwtTokenType {
  USER_AUTHENTICATION = 'USER_AUTHENTICATION',
  USER_SIGN_UP = 'USER_SIGN_UP',
  USER_RESET_EMAIL = 'USER_RESET_EMAIL',
  USER_RESET_USERNAME = 'USER_RESET_USERNAME',
  USER_RESET_PASSWORD = 'USER_RESET_PASSWORD',
}

export const AuthServiceErrorPrefix = 100;
