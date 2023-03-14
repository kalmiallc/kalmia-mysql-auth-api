"use strict";
/* eslint-disable no-shadow */
Object.defineProperty(exports, "__esModule", { value: true });
exports.AuthServiceErrorPrefix = exports.AuthJwtTokenType = exports.AuthAuthenticationErrorCode = exports.AuthResourceNotFoundErrorCode = exports.AuthSystemErrorCode = exports.AuthBadRequestErrorCode = exports.AuthValidatorErrorCode = exports.PermissionLevel = exports.PermissionType = exports.AuthDbTables = void 0;
/**
 * List of authentication service database tables.
 */
var AuthDbTables;
(function (AuthDbTables) {
    AuthDbTables["USERS"] = "authUser";
    AuthDbTables["TOKENS"] = "authToken";
    AuthDbTables["ROLES"] = "authRole";
    AuthDbTables["USER_ROLES"] = "authUserRole";
    AuthDbTables["ROLE_PERMISSIONS"] = "authRolePermission";
})(AuthDbTables = exports.AuthDbTables || (exports.AuthDbTables = {}));
/**
 * Permission types definitions.
 */
var PermissionType;
(function (PermissionType) {
    PermissionType["READ"] = "read";
    PermissionType["WRITE"] = "write";
    PermissionType["EXECUTE"] = "execute";
})(PermissionType = exports.PermissionType || (exports.PermissionType = {}));
/**
 * Permissions levels definitions.
 */
var PermissionLevel;
(function (PermissionLevel) {
    PermissionLevel[PermissionLevel["NONE"] = 0] = "NONE";
    PermissionLevel[PermissionLevel["OWN"] = 1] = "OWN";
    PermissionLevel[PermissionLevel["ALL"] = 2] = "ALL";
})(PermissionLevel = exports.PermissionLevel || (exports.PermissionLevel = {}));
/**
 * Auth validator Error codes - 100_422000.
 */
var AuthValidatorErrorCode;
(function (AuthValidatorErrorCode) {
    AuthValidatorErrorCode[AuthValidatorErrorCode["DEFAULT_VALIDATION_ERROR"] = 100422000] = "DEFAULT_VALIDATION_ERROR";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_EMAIL_NOT_PRESENT"] = 100422001] = "USER_EMAIL_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_EMAIL_NOT_VALID"] = 100422002] = "USER_EMAIL_NOT_VALID";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_EMAIL_ALREADY_TAKEN"] = 100422003] = "USER_EMAIL_ALREADY_TAKEN";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_PASSWORD_NOT_PRESENT"] = 100422004] = "USER_PASSWORD_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_PASSWORD_NOT_VALID"] = 100422005] = "USER_PASSWORD_NOT_VALID";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_ID_NOT_PRESENT"] = 100422006] = "USER_ID_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_ID_ALREADY_TAKEN"] = 100422007] = "USER_ID_ALREADY_TAKEN";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_USERNAME_NOT_PRESENT"] = 100422008] = "USER_USERNAME_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_USERNAME_NOT_VALID"] = 100422009] = "USER_USERNAME_NOT_VALID";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_USERNAME_ALREADY_TAKEN"] = 100422010] = "USER_USERNAME_ALREADY_TAKEN";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_ROLE_ID_NOT_PRESENT"] = 100422011] = "ROLE_PERMISSION_ROLE_ID_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_PERMISSION_ID_NOT_PRESENT"] = 100422012] = "ROLE_PERMISSION_PERMISSION_ID_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_READ_LEVEL_NOT_SET"] = 100422013] = "ROLE_PERMISSION_READ_LEVEL_NOT_SET";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_WRITE_LEVEL_NOT_SET"] = 100422014] = "ROLE_PERMISSION_WRITE_LEVEL_NOT_SET";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET"] = 100422015] = "ROLE_PERMISSION_EXECUTE_LEVEL_NOT_SET";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_NAME_NOT_PRESENT"] = 100422016] = "ROLE_PERMISSION_NAME_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_NAME_NOT_PRESENT"] = 100422017] = "ROLE_NAME_NOT_PRESENT";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_NAME_ALREADY_TAKEN"] = 100422018] = "ROLE_NAME_ALREADY_TAKEN";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_PIN_NOT_CORRECT_LENGTH"] = 100422019] = "USER_PIN_NOT_CORRECT_LENGTH";
    AuthValidatorErrorCode[AuthValidatorErrorCode["USER_PIN_ALREADY_TAKEN"] = 100422020] = "USER_PIN_ALREADY_TAKEN";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_READ_LEVEL_NOT_VALID"] = 100422021] = "ROLE_PERMISSION_READ_LEVEL_NOT_VALID";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID"] = 100422022] = "ROLE_PERMISSION_WRITE_LEVEL_NOT_VALID";
    AuthValidatorErrorCode[AuthValidatorErrorCode["ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID"] = 100422023] = "ROLE_PERMISSION_EXECUTE_LEVEL_NOT_VALID";
})(AuthValidatorErrorCode = exports.AuthValidatorErrorCode || (exports.AuthValidatorErrorCode = {}));
/**
 * Bad request error codes - 100_400000.
 */
var AuthBadRequestErrorCode;
(function (AuthBadRequestErrorCode) {
    AuthBadRequestErrorCode[AuthBadRequestErrorCode["DEFAULT_BAD_REQUEST_ERROR"] = 100400000] = "DEFAULT_BAD_REQUEST_ERROR";
    AuthBadRequestErrorCode[AuthBadRequestErrorCode["MISSING_DATA_ERROR"] = 100400001] = "MISSING_DATA_ERROR";
    AuthBadRequestErrorCode[AuthBadRequestErrorCode["ROLE_PERMISSION_ALREADY_EXISTS"] = 100400002] = "ROLE_PERMISSION_ALREADY_EXISTS";
    AuthBadRequestErrorCode[AuthBadRequestErrorCode["AUTH_USER_ROLE_ALREADY_EXISTS"] = 100400003] = "AUTH_USER_ROLE_ALREADY_EXISTS";
    AuthBadRequestErrorCode[AuthBadRequestErrorCode["AUTH_USER_ROLE_DOES_NOT_EXISTS"] = 100400004] = "AUTH_USER_ROLE_DOES_NOT_EXISTS";
})(AuthBadRequestErrorCode = exports.AuthBadRequestErrorCode || (exports.AuthBadRequestErrorCode = {}));
/**
 * System error codes - 500000.
 */
var AuthSystemErrorCode;
(function (AuthSystemErrorCode) {
    AuthSystemErrorCode[AuthSystemErrorCode["DEFAULT_SYSTEM_ERROR"] = 100500000] = "DEFAULT_SYSTEM_ERROR";
    AuthSystemErrorCode[AuthSystemErrorCode["UNHANDLED_SYSTEM_ERROR"] = 100500001] = "UNHANDLED_SYSTEM_ERROR";
    AuthSystemErrorCode[AuthSystemErrorCode["SQL_SYSTEM_ERROR"] = 100500002] = "SQL_SYSTEM_ERROR";
})(AuthSystemErrorCode = exports.AuthSystemErrorCode || (exports.AuthSystemErrorCode = {}));
/**
 * Resource not found error codes - 404000.
 */
var AuthResourceNotFoundErrorCode;
(function (AuthResourceNotFoundErrorCode) {
    AuthResourceNotFoundErrorCode[AuthResourceNotFoundErrorCode["DEFAULT_RESOURCE_NOT_FOUND_ERROR"] = 100404000] = "DEFAULT_RESOURCE_NOT_FOUND_ERROR";
    AuthResourceNotFoundErrorCode[AuthResourceNotFoundErrorCode["AUTH_USER_DOES_NOT_EXISTS"] = 100404001] = "AUTH_USER_DOES_NOT_EXISTS";
    AuthResourceNotFoundErrorCode[AuthResourceNotFoundErrorCode["ROLE_DOES_NOT_EXISTS"] = 100404002] = "ROLE_DOES_NOT_EXISTS";
    AuthResourceNotFoundErrorCode[AuthResourceNotFoundErrorCode["ROLE_PERMISSION_DOES_NOT_EXISTS"] = 100404003] = "ROLE_PERMISSION_DOES_NOT_EXISTS";
})(AuthResourceNotFoundErrorCode = exports.AuthResourceNotFoundErrorCode || (exports.AuthResourceNotFoundErrorCode = {}));
/**
 * Authentication error codes - 401000.
 */
var AuthAuthenticationErrorCode;
(function (AuthAuthenticationErrorCode) {
    AuthAuthenticationErrorCode[AuthAuthenticationErrorCode["MISSING_AUTHENTICATION_TOKEN"] = 100401001] = "MISSING_AUTHENTICATION_TOKEN";
    AuthAuthenticationErrorCode[AuthAuthenticationErrorCode["INVALID_TOKEN"] = 100401002] = "INVALID_TOKEN";
    AuthAuthenticationErrorCode[AuthAuthenticationErrorCode["USER_NOT_AUTHENTICATED"] = 100401003] = "USER_NOT_AUTHENTICATED";
})(AuthAuthenticationErrorCode = exports.AuthAuthenticationErrorCode || (exports.AuthAuthenticationErrorCode = {}));
/**
 * Authentication JWT token types definitions.
 */
var AuthJwtTokenType;
(function (AuthJwtTokenType) {
    AuthJwtTokenType["USER_AUTHENTICATION"] = "USER_AUTHENTICATION";
    AuthJwtTokenType["USER_SIGN_UP"] = "USER_SIGN_UP";
    AuthJwtTokenType["USER_RESET_EMAIL"] = "USER_RESET_EMAIL";
    AuthJwtTokenType["USER_RESET_USERNAME"] = "USER_RESET_USERNAME";
    AuthJwtTokenType["USER_RESET_PASSWORD"] = "USER_RESET_PASSWORD";
    AuthJwtTokenType["USER_LOGIN_MAGIC"] = "USER_LOGIN_MAGIC";
})(AuthJwtTokenType = exports.AuthJwtTokenType || (exports.AuthJwtTokenType = {}));
exports.AuthServiceErrorPrefix = 100;
//# sourceMappingURL=types.js.map