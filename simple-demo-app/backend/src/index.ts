import express from "express";
import cookieParser from "cookie-parser";
import cors from "cors";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { config } from "dotenv";
import path from "path";
import { Issuer, Client, generators } from "openid-client";
import crypto from "crypto";

// Load environment variables
if (process.env.NODE_ENV !== "production") {
  config(); // .env dev config
  // production node image loads backend.prod.env automatically
}

// Constants
const JWT_EXPIRATION = "15m"; // session token expiration
const PKCE_COOKIE_MAX_AGE = 10 * 60 * 1000; // login cookie age ( 10 minutes )

// Environment variables with validation
const ENV = {
  PORT: parseInt(process.env.PORT || "3001"),
  NODE_ENV: process.env.NODE_ENV || "development",
  PROXY_EXISTS: process.env.PROXY_EXISTS || "0",
  DOCKER_EXISTS: process.env.DOCKER_EXISTS || "0",
  FRONTEND_URL: process.env.FRONTEND_URL,
  JWT_SECRET: process.env.JWT_SECRET,
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY,
  OIDC_CONFIG: {
    ISSUER_URL: process.env.ISSUER_URL,
    CLIENT_ID: process.env.CLIENT_ID,
    CLIENT_SECRET: process.env.CLIENT_SECRET,
    CALLBACK_URL: process.env.CALLBACK_URL,
  },
} as const;

// Type definitions
interface User {
  id: string;
  email: string;
  preferred_username: string;
  roles?: string[];
  idToken?: string;
}

interface PKCEData {
  codeVerifier: string;
  state: string;
}

interface JWTPayload {
  id: string;
  email: string;
  roles?: string[];
  oidcRefreshToken: string;
}

interface AuthError {
  error: string;
  requiresReauth?: boolean;
  reason?: string;
}

// Extend Express types
declare global {
  namespace Express {
    interface User {
      id: string;
      email: string;
      preferred_username: string;
      roles?: string[];
      idToken?: string;
    }

    interface Request {
      user?: User;
    }
  }
}

// Custom error classes
class AuthenticationError extends Error {
  constructor(message: string, public statusCode: number = 401) {
    super(message);
    this.name = "AuthenticationError";
  }
}

class ValidationError extends Error {
  constructor(message: string, public statusCode: number = 400) {
    super(message);
    this.name = "ValidationError";
  }
}

// Utility functions
class CryptoService {
  private static readonly algorithm = "aes-256-cbc";
  private static readonly IV_LENGTH = 16;
  private static readonly key = ENV.ENCRYPTION_KEY as string;

  static encrypt(text: string): string {
    try {
      const iv = crypto.randomBytes(this.IV_LENGTH);
      const cipher = crypto.createCipheriv(this.algorithm, this.key, iv);
      let encrypted = cipher.update(text, "utf8", "hex");
      encrypted += cipher.final("hex");
      return `${iv.toString("hex")}:${encrypted}`;
    } catch (error) {
      console.error("Encryption failed:", error);
      throw new Error("Encryption failed");
    }
  }

  static decrypt(text: string): string {
    try {
      const [ivHex, encryptedText] = text.split(":");
      if (!ivHex || !encryptedText) {
        throw new Error("Invalid encrypted text format");
      }

      const iv = Buffer.from(ivHex, "hex");
      const decipher = crypto.createDecipheriv(this.algorithm, this.key, iv);
      let decrypted = decipher.update(encryptedText, "hex", "utf8");
      decrypted += decipher.final("utf8");
      return decrypted;
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Decryption failed");
    }
  }
}

class JWTService {
  private static readonly secret = ENV.JWT_SECRET!;

  static generate(user: User, oidcRefreshToken: string): string {
    const encryptedRefreshToken = CryptoService.encrypt(oidcRefreshToken);

    const payload: JWTPayload = {
      id: user.id,
      email: user.email,
      roles: user.roles,
      oidcRefreshToken: encryptedRefreshToken,
    };

    return jwt.sign(payload, this.secret, { expiresIn: JWT_EXPIRATION });
  }

  static verify(token: string): Promise<JWTPayload> {
    return new Promise((resolve, reject) => {
      jwt.verify(token, this.secret, (err, decoded) => {
        if (err) {
          reject(err);
        } else {
          resolve(decoded as JWTPayload);
        }
      });
    });
  }
}

class CookieService {
  static storePKCE(
    res: express.Response,
    codeVerifier: string,
    state: string
  ): void {
    const pkceData: PKCEData = { codeVerifier, state };
    const encryptedPKCE = CryptoService.encrypt(JSON.stringify(pkceData));

    res.cookie("pkce_data", encryptedPKCE, {
      httpOnly: true,
      secure: ENV.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: PKCE_COOKIE_MAX_AGE,
    });
  }

  static retrievePKCE(req: express.Request): PKCEData | null {
    const encryptedPKCE = req.cookies.pkce_data;
    if (!encryptedPKCE) {
      return null;
    }

    try {
      const decryptedData = CryptoService.decrypt(encryptedPKCE);
      return JSON.parse(decryptedData) as PKCEData;
    } catch (error) {
      console.error("Failed to decrypt PKCE data:", error);
      return null;
    }
  }

  static clearPKCE(res: express.Response): void {
    res.clearCookie("pkce_data", {
      httpOnly: true,
      secure: ENV.NODE_ENV === "production",
      sameSite: "lax",
    });
  }
}

// OIDC Client management
class OIDCClientManager {
  private static issuer: any;
  private static client: Client;

  static async initialize(): Promise<void> {
    try {
      this.issuer = await Issuer.discover(ENV.OIDC_CONFIG.ISSUER_URL!);
      console.log("Discovered issuer:", this.issuer.issuer);

      this.client = new this.issuer.Client({
        client_id: ENV.OIDC_CONFIG.CLIENT_ID,
        client_secret: ENV.OIDC_CONFIG.CLIENT_SECRET,
        redirect_uris: [ENV.OIDC_CONFIG.CALLBACK_URL],
        response_types: ["code"],
      });

      console.log("OIDC Client initialized successfully");
    } catch (error) {
      console.error("Failed to initialize OIDC client:", error);
      throw error;
    }
  }

  static getClient(): Client {
    if (!this.client) {
      throw new Error("OIDC Client not initialized");
    }
    return this.client;
  }
}

// Authentication service
class AuthService {
  static async refreshToken(
    req: express.Request,
    res: express.Response,
    decoded: JWTPayload
  ): Promise<boolean> {
    try {
      const { oidcRefreshToken: encryptedRefreshToken } = decoded;

      if (!encryptedRefreshToken) {
        return false;
      }

      const oidcRefreshToken = CryptoService.decrypt(encryptedRefreshToken);
      const client = OIDCClientManager.getClient();
      const refreshedTokenSet = await client.refresh(oidcRefreshToken);

      const newClaims = refreshedTokenSet.claims();
      const newIdTokenDecoded = jwt.decode(
        refreshedTokenSet.id_token as string
      ) as any;

      const refreshedUser: User = {
        id: newClaims.sub || decoded.id,
        email: newClaims.email || decoded.email,
        preferred_username:
          newClaims.preferred_username || decoded.email?.split("@")[0] || "",
        roles: newIdTokenDecoded?.realm_access?.roles || decoded.roles || [],
      };

      const newSessionAccessToken = JWTService.generate(
        refreshedUser,
        refreshedTokenSet.refresh_token as string
      );

      res.setHeader("X-New-Access-Token", newSessionAccessToken);
      res.setHeader("X-Token-Refreshed", "true");

      req.user = refreshedUser;
      return true;
    } catch (refreshError) {
      console.error("Token refresh failed:", refreshError);
      return false;
    }
  }

  static extractToken(req: express.Request): string | null {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    return authHeader.substring(7);
  }
}

// Middleware
const extractTokenForLogout = (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void => {
  const token = AuthService.extractToken(req);

  if (!token) {
    return next();
  }

  JWTService.verify(token)
    .then((decoded) => {
      req.user = decoded as any;
      next();
    })
    .catch(() => {
      next(); // Continue even if token is invalid for logout
    });
};

const verifyTokenWithAutoRefresh = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): Promise<void> => {
  const token = AuthService.extractToken(req);

  if (!token) {
    res
      .status(400)
      .json({ error: "Access token required" } satisfies AuthError);
    return;
  }

  try {
    const decoded = await JWTService.verify(token);
    req.user = decoded as any;
    next();
  } catch (err: any) {
    // If token is expired, try to refresh it
    if (err.name === "TokenExpiredError") {
      const decodedExpired = jwt.decode(token) as JWTPayload;
      if (await AuthService.refreshToken(req, res, decodedExpired)) {
        return next();
      }

      res.status(401).json({
        error: "Session expired",
        requiresReauth: true,
        reason: "sso_logout",
      } satisfies AuthError);
      return;
    }

    res.status(400).json({ error: "Invalid token" } satisfies AuthError);
  }
};

const requireRole = (role: string) => {
  return (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ): void => {
    const user = req.user as User;

    if (!user?.roles?.includes(role)) {
      res.status(403).json({ error: "Access denied" } satisfies AuthError);
      return;
    }

    next();
  };
};

// Express app setup
const createApp = (): express.Application => {
  const app = express();

  // Trust proxy configuration
  if (ENV.PROXY_EXISTS) {
    app.set("trust proxy", 1);
  }

  // Static files
  const staticPath =
    ENV.DOCKER_EXISTS === "1"
      ? "/app/public"
      : path.join(__dirname, "/../public");
  app.use(express.static(staticPath));

  // Security middleware
  app.use(helmet());
  app.use(
    cors({
      origin: ENV.FRONTEND_URL,
      credentials: true,
      methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      allowedHeaders: ["Content-Type", "Authorization", "Cookie"],
    })
  );

  // Body parsing middleware
  app.use(express.json({ limit: "10mb" }));
  app.use(express.urlencoded({ extended: true, limit: "10mb" }));
  app.use(cookieParser());

  // Routes
  setupRoutes(app, staticPath);

  // Error handling
  setupErrorHandling(app);

  return app;
};

// Route handlers
const setupRoutes = (app: express.Application, staticPath: string): void => {
  // Health check
  app.get("/api/health", (req, res) => {
    res.json({
      status: "OK",
      timestamp: new Date().toISOString(),
      environment: ENV.NODE_ENV,
    });
  });

  // Authentication routes
  app.get("/api/auth/jwt/login", handleLogin);
  app.get("/api/auth/jwt/callback", handleCallback);
  app.get("/api/auth/jwt/logout", extractTokenForLogout, handleLogout);
  app.post("/api/auth/jwt/refresh", handleRefresh);

  // Protected routes
  app.get("/api/user", verifyTokenWithAutoRefresh, handleGetUser);
  app.get(
    "/api/admin/resource",
    verifyTokenWithAutoRefresh,
    requireRole("admin"),
    handleAdminResource
  );

  // Frontend fallback
  app.use(/(.*)/, (req, res) => {
    if (req.path.startsWith("/api")) {
      return res.status(404).json({ error: "API route not found" });
    }
    return res.sendFile(path.join(staticPath, "index.html"));
  });
};

// handler for /api/auth/jwt/login
const handleLogin = (req: express.Request, res: express.Response): void => {
  try {
    const codeVerifier = generators.codeVerifier();
    const codeChallenge = generators.codeChallenge(codeVerifier);
    const state = generators.state();

    CookieService.storePKCE(res, codeVerifier, state);

    const client = OIDCClientManager.getClient();
    const authUrl = client.authorizationUrl({
      scope: "openid email profile",
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state: state,
    });

    res.redirect(authUrl);
  } catch (error) {
    console.error("Error initiating OIDC login:", error);
    res.status(500).json({ error: "Failed to initiate login" });
  }
};

// handler for /api/auth/jwt/callback
const handleCallback = async (
  req: express.Request,
  res: express.Response
): Promise<void> => {
  try {
    const client = OIDCClientManager.getClient();
    const params = client.callbackParams(req);
    const pkceData = CookieService.retrievePKCE(req);

    CookieService.clearPKCE(res);

    if (!pkceData) {
      res.status(400).json({ error: "PKCE data not found or expired" });
      return;
    }

    if (params.state !== pkceData.state) {
      res.status(400).json({ error: "Invalid state parameter" });
      return;
    }

    const tokenSet = await client.callback(
      ENV.OIDC_CONFIG.CALLBACK_URL!,
      params,
      {
        code_verifier: pkceData.codeVerifier,
        state: params.state,
      }
    );

    const claims = tokenSet.claims();
    const idTokenDecoded = jwt.decode(tokenSet.id_token as string) as any;

    const user: User = {
      id: claims.sub || "",
      email: claims.email || "",
      preferred_username:
        claims.preferred_username || claims.email?.split("@")[0] || "",
      roles: idTokenDecoded?.realm_access?.roles || [],
      idToken: tokenSet.id_token as string,
    };

    const sessionAccessToken = JWTService.generate(
      user,
      tokenSet.refresh_token as string
    );

    res.redirect(
      `${ENV.FRONTEND_URL}/auth/callback?token=${sessionAccessToken}`
    );
  } catch (error) {
    console.error("OIDC callback error:", error);
    res.status(500).json({ error: "Authentication failed" });
  }
};

// handler for /api/auth/jwt/logout
const handleLogout = (req: express.Request, res: express.Response): void => {
  if (req.user?.idToken) {
    const client = OIDCClientManager.getClient();
    const logoutUrl = client.endSessionUrl({
      post_logout_redirect_uri: ENV.FRONTEND_URL,
      id_token_hint: req.user.idToken,
    });

    res.redirect(logoutUrl);
    return;
  }

  res.redirect(ENV.FRONTEND_URL!);
};

const handleRefresh = async (
  req: express.Request,
  res: express.Response
): Promise<void> => {
  const token = AuthService.extractToken(req);

  if (!token) {
    res.status(400).json({ error: "Access token required" });
    return;
  }

  try {
    const decoded = await JWTService.verify(token);

    if (await AuthService.refreshToken(req, res, decoded)) {
      res.status(200).json({ message: "Token refreshed successfully" });
    } else {
      res.status(401).json({
        error: "Session expired",
        requiresReauth: true,
        reason: "sso_logout",
      });
    }
  } catch (err: any) {
    if (err.name === "TokenExpiredError") {
      const decodedExpired = jwt.decode(token) as JWTPayload;

      if (await AuthService.refreshToken(req, res, decodedExpired)) {
        res.status(200).json({ message: "Token refreshed successfully" });
        return;
      }
    }

    res.status(401).json({
      error: "Session expired",
      requiresReauth: true,
      reason: "sso_logout",
    });
  }
};

const handleGetUser = (req: express.Request, res: express.Response): void => {
  const user = req.user as any;
  res.json({ user: user });
};

const handleAdminResource = (
  req: express.Request,
  res: express.Response
): void => {
  res.json({
    message: "Admin resource accessed successfully",
    timestamp: new Date().toISOString(),
    user: req.user?.email,
  });
};

// Error handling
const setupErrorHandling = (app: express.Application): void => {
  app.use(
    (
      err: any,
      req: express.Request,
      res: express.Response,
      next: express.NextFunction
    ) => {
      console.error("Unhandled error:", err);

      if (
        err instanceof AuthenticationError ||
        err instanceof ValidationError
      ) {
        res.status(err.statusCode).json({ error: err.message });
        return;
      }

      res.status(500).json({
        error:
          ENV.NODE_ENV === "production" ? "Internal server error" : err.message,
      });
    }
  );
};

// Application startup
const startServer = async (): Promise<void> => {
  try {
    // Initialize OIDC client
    await OIDCClientManager.initialize();

    // Create and start Express app
    const app = createApp();

    app.listen(ENV.PORT, () => {
      console.log(`Server running on http://localhost:${ENV.PORT}`);
      console.log(`Environment: ${ENV.NODE_ENV}`);
      console.log(
        `Keycloak OIDC configured for: ${ENV.OIDC_CONFIG.ISSUER_URL}`
      );
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
};

// Start the application
if (require.main === module) {
  startServer().catch((error) => {
    console.error("Application startup failed:", error);
    process.exit(1);
  });
}

export default createApp;
