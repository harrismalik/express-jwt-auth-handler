import { sign, verify, TokenExpiredError, SignOptions } from 'jsonwebtoken';
import { CookieOptions, Response } from 'express';
import {
    AuthConfig,
    RefreshTokenData,
    AccessTokenData,
    TokenPair,
    TokenCheckResult,
    TokenRenewalCallback
} from './types';
import { DEFAULT_CONFIG, COOKIE_NAMES } from './constants';
import {AuthError} from "./utils";

export class Auth {
    private readonly accessTokenSecret: string;
    private readonly refreshTokenSecret: string;
    private readonly config: Required<Omit<AuthConfig, 'accessTokenSecret' | 'refreshTokenSecret'>>;

    /**
     * Initialize the Auth instance with configuration
     * @param config - Authentication configuration
     */
    constructor(config: AuthConfig) {
        if (!config.accessTokenSecret || !config.refreshTokenSecret) {
            throw new AuthError('Access token and refresh token secrets are required');
        }

        this.accessTokenSecret = config.accessTokenSecret;
        this.refreshTokenSecret = config.refreshTokenSecret;
        this.config = {
            ...DEFAULT_CONFIG,
            accessTokenExpiresIn: config.accessTokenExpiresIn ?? DEFAULT_CONFIG.accessTokenExpiresIn,
            refreshTokenExpiresIn: config.refreshTokenExpiresIn ?? DEFAULT_CONFIG.refreshTokenExpiresIn,
            cookieSecure: config.cookieSecure ?? DEFAULT_CONFIG.cookieSecure,
            cookieSameSite: config.cookieSameSite ?? DEFAULT_CONFIG.cookieSameSite,
            cookiePath: config.cookiePath ?? DEFAULT_CONFIG.cookiePath,
            cookieDomain: config.cookieDomain as string,
        };
    }

    /**
     * Creates both access and refresh tokens for a user
     * @param userId - Unique identifier for the user
     * @param tokenVersion - Version number for the refresh token
     * @returns Object containing both tokens
     */
    async createAuthTokens(userId: string, tokenVersion: number): Promise<TokenPair> {
        try {
            const accessToken = sign(
                { userId } as AccessTokenData,
                this.accessTokenSecret,
                { expiresIn: this.config.accessTokenExpiresIn } as SignOptions
            );

            const refreshToken = sign(
                { userId, tokenVersion } as RefreshTokenData,
                this.refreshTokenSecret,
                { expiresIn: this.config.refreshTokenExpiresIn } as SignOptions
            );

            return { accessToken, refreshToken };
        } catch (error) {
            throw new AuthError('Failed to create auth tokens');
        }
    }

    /**
     * Sets secure HTTP-only cookies for both tokens
     * @param res - Express response object
     * @param tokens - Object containing access and refresh tokens
     */
    sendAuthCookies(res: Response, tokens: TokenPair): void {
        const cookieOptions: CookieOptions = {
            httpOnly: true,
            secure: this.config.cookieSecure,
            sameSite: this.config.cookieSameSite,
            path: this.config.cookiePath,
            domain: this.config.cookieDomain,
        };

        // Access token cookie
        res.cookie(COOKIE_NAMES.accessToken, tokens.accessToken, {
            ...cookieOptions,
            maxAge: this.parseDuration(this.config.accessTokenExpiresIn),
        });

        // Refresh token cookie
        res.cookie(COOKIE_NAMES.refreshToken, tokens.refreshToken, {
            ...cookieOptions,
            maxAge: this.parseDuration(this.config.refreshTokenExpiresIn),
        });
    }

    /**
     * Clears auth cookies
     * @param res - Express response object
     */
    clearAuthCookies(res: Response): void {
        const cookieOptions: CookieOptions = {
            httpOnly: true,
            secure: this.config.cookieSecure,
            sameSite: this.config.cookieSameSite,
            path: this.config.cookiePath,
            domain: this.config.cookieDomain,
        };

        res.clearCookie(COOKIE_NAMES.accessToken, cookieOptions);
        res.clearCookie(COOKIE_NAMES.refreshToken, cookieOptions);
    }

    /**
     * Verifies and potentially renews tokens based on their validity
     * @param accessToken - JWT access token
     * @param refreshToken - JWT refresh token
     * @param expectedTokenVersion - Expected version of the refresh token
     * @param renewalCallback - Optional callback for token renewal when both tokens are expired
     * @returns Object containing decoded token data and optionally new tokens
     */
    async checkTokens(
        accessToken: string,
        refreshToken: string,
        expectedTokenVersion: number,
        renewalCallback?: TokenRenewalCallback
    ): Promise<TokenCheckResult> {
        try {
            try {
                // Checking the access token validity
                const accessTokenData = verify(
                    accessToken,
                    this.accessTokenSecret
                ) as AccessTokenData;

                // If access token is valid, verify refresh token
                const refreshTokenData = verify(
                    refreshToken,
                    this.refreshTokenSecret
                ) as RefreshTokenData;

                // Check token version
                if (refreshTokenData.tokenVersion !== expectedTokenVersion) {
                    throw new AuthError('Invalid refresh token version');
                }

                // Both tokens are valid
                return { accessTokenData, refreshTokenData };

            } catch (error) {
                // Handle access token expiration
                if (error instanceof TokenExpiredError) {
                    try {
                        // Verify refresh token
                        const refreshTokenData = verify(
                            refreshToken,
                            this.refreshTokenSecret
                        ) as RefreshTokenData;

                        // Check token version
                        if (refreshTokenData.tokenVersion !== expectedTokenVersion) {
                            throw new AuthError('Invalid refresh token version');
                        }

                        // Creating new access token
                        const newAccessToken = sign(
                            { userId: refreshTokenData.userId } as AccessTokenData,
                            this.accessTokenSecret,
                            { expiresIn: this.config.accessTokenExpiresIn } as SignOptions
                        );

                        return {
                            accessTokenData: { userId: refreshTokenData.userId } as AccessTokenData,
                            refreshTokenData,
                            tokens: {
                                accessToken: newAccessToken,
                                refreshToken // Returning existing refresh token
                            }
                        };
                    } catch (refreshError) {
                        // Both tokens are invalid/expired
                        if (renewalCallback) {
                            try {
                                // Get fresh user data from callback
                                const { userId, tokenVersion } = await renewalCallback();

                                // Create new token pair
                                const newTokens = await this.createAuthTokens(userId, tokenVersion);

                                return {
                                    accessTokenData: { userId } as AccessTokenData,
                                    refreshTokenData: { userId, tokenVersion } as RefreshTokenData,
                                    tokens: newTokens
                                };
                            } catch (callbackError) {
                                throw new AuthError('Token renewal failed');
                            }
                        }
                        throw new AuthError('Invalid tokens');
                    }
                }
                throw new AuthError('Invalid access token');
            }
        } catch (error) {
            if (error instanceof AuthError) {
                throw error;
            }
            throw new AuthError('Token verification failed');
        }
    }

    /**
     * Helper method to parse duration strings into milliseconds
     * @private
     */
    private parseDuration(duration: string): number {
        try {
            const units: { [key: string]: number } = {
                s: 1000,
                m: 60 * 1000,
                h: 60 * 60 * 1000,
                d: 24 * 60 * 60 * 1000,
            };

            const match = duration.match(/^(\d+)([smhd])$/);
            if (!match) {
                throw new Error('Invalid duration format');
            }

            const [, value, unit] = match;
            // Ensure unit is a valid key in the units object
            if (!unit || !units[unit] || !value) {
                throw new Error('Invalid duration unit');
            }
            return parseInt(value) * units[unit];
        } catch (error) {
            throw error;
        }
    }
}