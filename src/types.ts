import { JwtPayload } from 'jsonwebtoken';

export interface RefreshTokenData extends JwtPayload {
    userId: string;
    tokenVersion: number;
}

export interface AccessTokenData extends JwtPayload {
    userId: string;
}

export interface TokenPair {
    accessToken: string;
    refreshToken: string;
}

export interface TokenCheckResult {
    accessTokenData: AccessTokenData;
    refreshTokenData: RefreshTokenData;
    tokens?: TokenPair;
}

export interface AuthConfig {
    accessTokenSecret: string;
    refreshTokenSecret: string;
    accessTokenExpiresIn?: string;
    refreshTokenExpiresIn?: string;
    cookieSecure?: boolean;
    cookieSameSite?: boolean | 'lax' | 'strict' | 'none';
    cookiePath?: string;
    cookieDomain?: string;
}

export type TokenRenewalCallback = () => Promise<{
    userId: string;
    tokenVersion: number;
}>;