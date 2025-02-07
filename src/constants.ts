export const DEFAULT_CONFIG = {
    accessTokenExpiresIn: '15m',
    refreshTokenExpiresIn: '7d',
    cookieSecure: true,
    cookieSameSite: 'lax' as const,
    cookiePath: '/',
};

export const COOKIE_NAMES = {
    accessToken: 'access_token',
    refreshToken: 'refresh_token',
} as const;