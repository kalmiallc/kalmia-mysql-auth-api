import { AuthAuthenticationErrorCode, AuthBadRequestErrorCode, AuthResourceNotFoundErrorCode, AuthSystemErrorCode, AuthValidatorErrorCode } from '../../../config/types';
/**
 * Authorization service response.
 */
export interface IAuthResponse<T> {
    status: boolean;
    data?: T;
    errors?: (AuthValidatorErrorCode | AuthBadRequestErrorCode | AuthAuthenticationErrorCode | AuthSystemErrorCode | AuthResourceNotFoundErrorCode)[];
    details?: any;
}
//# sourceMappingURL=auth-response.interface.d.ts.map