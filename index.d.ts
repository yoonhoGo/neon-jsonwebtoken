export function sign(
  payload: object,
  key: string,
  options?: SignOptions,
): string;

export function decode(
  token: string,
  secretOrPublicKey: string,
  options: DecodeOptions & { complite: true },
): Jwt;
export function decode(
  token: string,
  secretOrPublicKey: string,
  options?: DecodeOptions,
): object;

export function verify(
  token: string,
  secretOrPublicKey: string,
  options: VerifyOptions & { complite: true },
): Jwt;
export function verify(
  token: string,
  secretOrPublicKey: string,
  options?: VerifyOptions,
): object;

export interface SignOptions {
  algorithm?: Algorithm | undefined;
  keyid?: string | undefined;
  expiresIn?: string | number | undefined;
  notBefore?: string | number | undefined;
  audience?: string | string[] | undefined;
  subject?: string | undefined;
  issuer?: string | undefined;
  jwtid?: string | undefined;
  noTimestamp?: boolean | undefined;
  header?: JwtHeader | undefined;
}

export interface DecodeOptions {
  complete?: boolean | undefined;
  json?: boolean | undefined;
}

export interface VerifyOptions {
  algorithms?: Algorithm[] | undefined;
  audience?: string | Array<string> | undefined;
  complete?: boolean | undefined;
  issuer?: string | string[] | undefined;
  ignoreExpiration?: boolean | undefined;
  ignoreNotBefore?: boolean | undefined;
  jwtid?: string | undefined;
  subject?: string | undefined;
}

export interface JwtHeader {
  alg: string | Algorithm;
  typ?: string | undefined;
  cty?: string | undefined;
  kid?: string | undefined;
  jku?: string | undefined;
  x5u?: string | string[] | undefined;
  x5t?: string | undefined;
}

export interface JwtPayload {
  [key: string]: any;
  iss?: string | undefined;
  sub?: string | undefined;
  aud?: string | string[] | undefined;
  exp?: number | undefined;
  nbf?: number | undefined;
  iat?: number | undefined;
  jti?: string | undefined;
}

export interface Jwt {
  header: JwtHeader;
  payload: JwtPayload | string;
  signature: string;
}

export type Algorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'PS256'
  | 'PS384'
  | 'PS512';
