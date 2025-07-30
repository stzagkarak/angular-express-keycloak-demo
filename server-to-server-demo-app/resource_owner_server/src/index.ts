// Resource Server - Express TypeScript Application
// File: resource-server/src/index.ts

import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import { Issuer, Client } from "openid-client";
import { config } from "dotenv";
import { jwtVerify, createRemoteJWKSet, KeyLike } from "jose"; // openid-client uses this library internally ( no need to npm i )

config(); // .env loading

const app = express();
const PORT = process.env.PORT || 3001;

// Keycloak configuration
const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || "";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "";
const KEYCLOAK_CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || "";
const KEYCLOAK_CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || "";

// Middleware
app.use(cors());
app.use(express.json());

// Global variables for OIDC client
let keycloakIssuer: any;
let client: Client;
let JWKS: any;

// Initialize OpenID Connect client
const initializeOIDCClient = async (): Promise<void> => {
  try {
    const issuerUrl = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}`;
    console.log(`Discovering OIDC configuration from: ${issuerUrl}`);

    keycloakIssuer = await Issuer.discover(issuerUrl);
    console.log("Discovered issuer:", keycloakIssuer.metadata.issuer);

    client = new keycloakIssuer.Client({
      client_id: KEYCLOAK_CLIENT_ID,
      client_secret: KEYCLOAK_CLIENT_SECRET,
    });

    console.log("OIDC client initialized successfully");
  } catch (error) {
    console.error("Failed to initialize OIDC client:", error);
    process.exit(1);
  }
};

const fetchCreateRemoteJWTSet = async (): Promise<void> => {
  // Build a JWKS fetcher from the discovered jwks_uri
  JWKS = createRemoteJWKSet(new URL(keycloakIssuer.metadata.jwks_uri));
};

// Interface for token introspection response
interface TokenIntrospectionResponse {
  active: boolean;
  client_id?: string;
  username?: string;
  scope?: string;
  exp?: number;
  iat?: number;
  sub?: string;
  aud?: string;
  iss?: string;
  token_type?: string;
}

// Token validation middleware
// Approach 1, call the introspect endpoint to have the Keycloak server verify the token
const validateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res
        .status(401)
        .json({ error: "Missing or invalid Authorization header" });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Introspect token using openid-client
    const tokenInfo = (await client.introspect(
      token
    )) as TokenIntrospectionResponse;

    console.log("Token introspection scopes:", tokenInfo.scope || "");

    if (!tokenInfo.active) {
      res.status(401).json({ error: "Invalid or expired token" });
      return;
    }

    // Add token info to request for potential use in handlers
    (req as any).tokenInfo = tokenInfo;
    next();
  } catch (error) {
    console.error("Token validation error:", error);
    res.status(500).json({ error: "Token validation failed" });
  }
};

// Token validation middleware
// Approach 2, verify the access token using the keycloak realm's public certs
const validateTokenLocal = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res
        .status(401)
        .json({ error: "Missing or invalid Authorization header" });
      return;
    }

    const token = authHeader.substring(7); // Remove 'Bearer ' prefix

    // Approach 2, call the introspect endpoint to have the Keycloak server verify the token
    console.log(KEYCLOAK_CLIENT_ID);

    const decoded = await jwtVerify(token, JWKS, {
      issuer: keycloakIssuer.metadata.issuer,
    }).catch(async (error) => {
      res.status(401).json({ error: "Invalid or expired token" });
      return;
    });

    // Add token info to request for potential use in handlers
    (req as any).tokenInfo = decoded;
    return next();
  } catch (error) {
    console.error("Token validation error:", error);
    res.status(500).json({ error: "Token validation failed" });
  }
};

// Health check endpoint (no auth required)
app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// Protected resource endpoint
app.get("/api/resource", validateTokenLocal, (req: Request, res: Response) => {
  const tokenInfo = (req as any).tokenInfo;

  res.json({
    message: "This is a protected resource!",
    data: {
      id: 1,
      name: "Demo Resource",
      description: "This resource is protected by OAuth 2.0",
      timestamp: new Date().toISOString(),
    },
    tokenInfo: {
      client_id: tokenInfo.client_id,
      scope: tokenInfo.scope,
      exp: tokenInfo.exp,
    },
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 handler
app.use("*", (req: Request, res: Response) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Initialize and start server
const startServer = async (): Promise<void> => {
  await initializeOIDCClient();
  await fetchCreateRemoteJWTSet();

  app.listen(PORT, () => {
    console.log(`Resource Server running on port ${PORT}`);
    console.log(`Keycloak Realm: ${KEYCLOAK_REALM}`);
    console.log(`Issuer: ${keycloakIssuer.metadata.issuer}`);
    console.log(`Health check: http://localhost:${PORT}/health`);
    console.log(`Protected resource: http://localhost:${PORT}/api/resource`);
  });
};

// Start the server
startServer().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});

export default app;
