export interface SignInParam {
  domain: string;
  userPoolId: string;
  region: string;
  clientId: string;
  identityProvider: string;
  idPoolId: string;
  redirectUri: string;
  code?: string;
  refreshToken?: string;
}

export interface SimpleLogger {
  error(message: string): void;
  info(message: string): void;
  warn(message: string): void;
  debug(message: string): void;
}
