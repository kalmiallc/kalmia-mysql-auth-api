import { AuthAuthenticationErrorCode, AuthBadRequestErrorCode, AuthResourceNotFoundErrorCode, AuthSystemErrorCode, AuthValidatorErrorCode } from '../../../config/types';

export interface IAuthResponse<T> {
  status: boolean;
  data?: T;
  errors?: (AuthValidatorErrorCode | AuthBadRequestErrorCode | AuthAuthenticationErrorCode | AuthSystemErrorCode | AuthResourceNotFoundErrorCode)[];
}
