/**
 * Auth user definition interface.
 */
export interface IAuthUser {
  status?: number;
  username?: string;
  email: string;
  password?: string;
  PIN?: string;
}
