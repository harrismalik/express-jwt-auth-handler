# Express JWT Auth Handler

A secure and flexible JWT authentication package for Express applications that handles both access and refresh tokens with cookie-based storage.

[![npm version](https://badge.fury.io/js/express-jwt-auth-handler.svg)](https://www.npmjs.com/package/express-jwt-auth-handler)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔐 Secure JWT-based authentication
- 🔄 Automatic token refresh mechanism
- 🍪 HTTP-only cookie management
- 📦 TypeScript support
- 🚀 Easy integration with Express
- 🛡️ Token version control for security
- ⚡ Lightweight with minimal dependencies

## Installation

```bash
npm install express-jwt-auth-handler
```

## Quick Start

```typescript
import express from 'express';
import { Auth } from 'express-jwt-auth-handler';

const app = express();

// Initialize auth handler
const auth = new Auth({
  accessTokenSecret: 'your-access-token-secret',
  refreshTokenSecret: 'your-refresh-token-secret',
});

// Example login route
app.post('/login', async (req, res) => {
  try {
    // Create tokens after successful login
    const tokens = await auth.createAuthTokens(userId, tokenVersion);
    
    // Set tokens as HTTP-only cookies
    auth.sendAuthCookies(res, tokens);
    
    res.json({ success: true });
  } catch (error) {
    res.status(401).json({ error: 'Authentication failed' });
  }
});
```

## Configuration

### Auth Configuration Options

```typescript
interface AuthConfig {
  accessTokenSecret: string;      // Required: Secret for access tokens
  refreshTokenSecret: string;     // Required: Secret for refresh tokens
  accessTokenExpiresIn?: string;  // Optional: Duration for access token (default: '15m')
  refreshTokenExpiresIn?: string; // Optional: Duration for refresh token (default: '7d')
  cookieSecure?: boolean;         // Optional: Secure cookie flag (default: true)
  cookieSameSite?: boolean | 'lax' | 'strict' | 'none'; // Optional: SameSite cookie policy (default: 'lax')
  cookiePath?: string;            // Optional: Cookie path (default: '/')
  cookieDomain?: string;          // Optional: Cookie domain
}
```

## API Reference

### Creating an Auth Instance

```typescript
const auth = new Auth({
  accessTokenSecret: 'your-access-token-secret',
  refreshTokenSecret: 'your-refresh-token-secret',
  // Optional configurations
  accessTokenExpiresIn: '30m',
  refreshTokenExpiresIn: '7d',
  cookieSecure: true,
  cookieSameSite: 'lax',
});
```

### Methods

#### `createAuthTokens(userId: string, tokenVersion: number): Promise<TokenPair>`

Creates a new pair of access and refresh tokens.

```typescript
const tokens = await auth.createAuthTokens('user123', 1);
// Returns: { accessToken: string, refreshToken: string }
```

#### `sendAuthCookies(res: Response, tokens: TokenPair): void`

Sets the tokens as HTTP-only cookies in the response.

```typescript
auth.sendAuthCookies(res, tokens);
```

#### `clearAuthCookies(res: Response): void`

Clears authentication cookies from the response.

```typescript
auth.clearAuthCookies(res);
```

#### `checkTokens(accessToken: string, refreshToken: string, expectedTokenVersion: number, renewalCallback?: TokenRenewalCallback): Promise<TokenCheckResult>`

Verifies and potentially renews tokens based on their validity.

```typescript
const result = await auth.checkTokens(
  accessToken,
  refreshToken,
  tokenVersion,
  async () => {
    // Optional callback for token renewal
    return { userId: 'user123', tokenVersion: 1 };
  }
);
```

### Token Duration Format

Token durations can be specified using the following format:
- `s`: seconds (e.g., '30s')
- `m`: minutes (e.g., '15m')
- `h`: hours (e.g., '24h')
- `d`: days (e.g., '7d')

## Complete Example

Here's a complete example showing how to integrate the auth handler with an Express application:

```typescript
import express from 'express';
import { Auth, AuthError } from 'express-jwt-auth-handler';

const app = express();
const auth = new Auth({
  accessTokenSecret: process.env.ACCESS_TOKEN_SECRET!,
  refreshTokenSecret: process.env.REFRESH_TOKEN_SECRET!,
});

// Login route
app.post('/login', async (req, res) => {
  try {
    // Validate user credentials here
    const userId = 'user123';
    const tokenVersion = 1;

    const tokens = await auth.createAuthTokens(userId, tokenVersion);
    auth.sendAuthCookies(res, tokens);

    res.json({ success: true });
  } catch (error) {
    res.status(401).json({ error: 'Login failed' });
  }
});

// Protected route middleware
const authMiddleware = async (req, res, next) => {
  try {
    const accessToken = req.cookies.access_token;
    const refreshToken = req.cookies.refresh_token;

    const result = await auth.checkTokens(
      accessToken,
      refreshToken,
      1, // Expected token version
      async () => {
        // Implement your token renewal logic here
        return { userId: 'user123', tokenVersion: 1 };
      }
    );

    // If new tokens were generated, set them
    if (result.tokens) {
      auth.sendAuthCookies(res, result.tokens);
    }

    req.user = { userId: result.accessTokenData.userId };
    next();
  } catch (error) {
    res.status(401).json({ error: 'Unauthorized' });
  }
};

// Protected route example
app.get('/protected', authMiddleware, (req, res) => {
  res.json({ message: 'Protected data', user: req.user });
});

// Logout route
app.post('/logout', (req, res) => {
  auth.clearAuthCookies(res);
  res.json({ success: true });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
```

## Error Handling

The package throws `AuthError` for various authentication-related issues. Always wrap authentication operations in try-catch blocks:

```typescript
try {
  const result = await auth.checkTokens(accessToken, refreshToken, tokenVersion);
} catch (error) {
  if (error instanceof AuthError) {
    // Handle authentication error
    console.error(error.message);
  } else {
    // Handle other errors
    console.error('Unexpected error:', error);
  }
}
```

## Security Considerations

1. Always use strong, unique secrets for access and refresh tokens
2. Store secrets securely (e.g., environment variables)
3. Use HTTPS in production (cookieSecure: true)
4. Implement proper token version control for security
5. Consider implementing rate limiting for token endpoints
6. Regularly rotate tokens and implement proper logout mechanisms

## License

MIT © [mharrismalik](https://mharrismalik.com)