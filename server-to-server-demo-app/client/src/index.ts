// Client Application - TypeScript with openid-client
// File: client-app/src/index.ts

import express, { Request, Response } from "express";
import { Issuer, Client, TokenSet } from "openid-client";
import fetch from "node-fetch";
import { config } from "dotenv";

config(); // .env loading

const app = express();
const PORT = process.env.PORT || 3002;

// Configuration
const KEYCLOAK_BASE_URL = process.env.KEYCLOAK_BASE_URL || "";
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || "";
const CLIENT_ID = process.env.CLIENT_ID || "";
const CLIENT_SECRET = process.env.CLIENT_SECRET || "";
const RESOURCE_SERVER_URL = process.env.RESOURCE_SERVER_URL || "";

// Global variables for OIDC client
let keycloakIssuer: any;
let client: Client;

// In-memory token storage (in production, use Redis or similar)
let tokenSet: TokenSet | null = null;

app.use(express.json());

// Initialize OpenID Connect client
async function initializeOIDCClient(): Promise<void> {
  try {
    const issuerUrl = `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}`;
    console.log(`Discovering OIDC configuration from: ${issuerUrl}`);

    keycloakIssuer = await Issuer.discover(issuerUrl);
    console.log("Discovered issuer:", keycloakIssuer.metadata.issuer);

    client = new keycloakIssuer.Client({
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    });

    console.log("OIDC client initialized successfully");
    console.log(
      "Supported grant types:",
      keycloakIssuer.metadata.grant_types_supported
    );
  } catch (error) {
    console.error("Failed to initialize OIDC client:", error);
    throw error;
  }
}

// Function to get access token using Client Credentials Flow
async function getAccessToken(): Promise<string> {
  try {
    console.log("Requesting new access token using client credentials...");

    // Use openid-client for client credentials grant
    tokenSet = await client.grant({
      grant_type: "client_credentials",
      scope: "openid", // Add any required scopes
    });

    console.log("Access token obtained successfully");
    console.log(`Token expires in: ${tokenSet.expires_in} seconds`);
    console.log(`Token type: ${tokenSet.token_type}`);

    return tokenSet.access_token!;
  } catch (error) {
    console.error("Failed to get access token:", error);
    throw new Error("Token acquisition failed");
  }
}

// Function to get valid access token (refresh if needed)
async function getValidToken(): Promise<string> {
  if (!tokenSet || tokenSet.expired()) {
    console.log("Token is missing or expired, requesting new token...");
    return await getAccessToken();
  }

  console.log("Using existing valid token");
  console.log(`Token expires in: ${tokenSet.expires_in} seconds`);
  return tokenSet.access_token!;
}

// Function to make authenticated request to resource server
async function fetchProtectedResource(endpoint: string): Promise<any> {
  try {
    const token = await getValidToken();

    console.log(`Making request to: ${RESOURCE_SERVER_URL}${endpoint}`);

    // Use fetch for HTTP requests
    const response = await fetch(`${RESOURCE_SERVER_URL}${endpoint}`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        console.log("Token might be invalid, clearing cache and retrying...");
        tokenSet = null;

        // Retry once with new token
        const newToken = await getValidToken();
        const retryResponse = await fetch(`${RESOURCE_SERVER_URL}${endpoint}`, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${newToken}`,
            "Content-Type": "application/json",
          },
        });

        if (!retryResponse.ok) {
          throw new Error(
            `HTTP ${retryResponse.status}: ${retryResponse.statusText}`
          );
        }

        return await retryResponse.json();
      }

      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (error: any) {
    console.error("Request failed:", error.message);
    throw error;
  }
}

// API Routes

// Health check
app.get("/health", (req: Request, res: Response) => {
  res.json({
    status: "healthy",
    timestamp: new Date().toISOString(),
    hasToken: !!tokenSet,
    tokenExpired: tokenSet ? tokenSet.expired() : true,
    issuer: keycloakIssuer ? keycloakIssuer.metadata.issuer : null,
  });
});

// Get access token (for testing)
app.post("/token", async (req: Request, res: Response) => {
  try {
    const token = await getAccessToken();
    res.json({
      message: "Token acquired successfully",
      hasToken: !!token,
      expiresIn: tokenSet!.expires_in,
      tokenType: tokenSet!.token_type,
      scope: tokenSet!.scope,
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Fetch demo resource
app.get("/fetch-resource", async (req: Request, res: Response) => {
  try {
    const data = await fetchProtectedResource("/api/resource");
    res.json({
      success: true,
      message: "Resource fetched successfully",
      data: data,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Token info endpoint
app.get("/token-info", (req: Request, res: Response) => {
  if (!tokenSet) {
    res.json({
      hasToken: false,
      tokenExpired: true,
      message: "No token available",
    });
    return;
  }

  res.json({
    hasToken: true,
    tokenExpired: tokenSet.expired(),
    expiresIn: tokenSet.expires_in,
    tokenType: tokenSet.token_type,
    scope: tokenSet.scope,
    expiresAt: tokenSet.expires_at
      ? new Date(tokenSet.expires_at * 1000).toISOString()
      : null,
    claims: tokenSet.claims ? tokenSet.claims() : null,
  });
});

// Introspect current token
app.get("/introspect-token", async (req: Request, res: Response) => {
  try {
    if (!tokenSet || !tokenSet.access_token) {
      res.status(400).json({ error: "No token available to introspect" });
      return;
    }

    const introspection = await client.introspect(tokenSet.access_token);
    res.json({
      success: true,
      introspection: introspection,
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Revoke token directly via Keycloak
// NOTE: You can only revoke tokens issued to the client itself, no other client's tokens.
app.post("/revoke-token-direct", async (req: Request, res: Response) => {
  try {
    const { token: tokenToRevoke } = req.body;

    if (!tokenToRevoke) {
      res
        .status(400)
        .json({ error: "Token to revoke must be provided in request body" });
      return;
    }

    console.log("Revoking token directly via Keycloak...");

    // Use openid-client to revoke token directly
    await client.revoke(tokenToRevoke);

    // If the revoked token is our current token, clear it
    if (tokenSet && tokenSet.access_token === tokenToRevoke) {
      tokenSet = null;
      console.log("Local token cleared as it was the revoked token");
    }

    res.json({
      success: true,
      message: "Token revoked successfully via direct Keycloak call",
      revokedToken: `${tokenToRevoke.substring(0, 10)}...`, // Show only first 10 chars for security
    });
  } catch (error: any) {
    res.status(500).json({
      success: false,
      error: error.message,
    });
  }
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: any) => {
  console.error("Unhandled error:", err);
  res.status(500).json({ error: "Internal server error" });
});

// 404 handler
app.use("*", (req: Request, res: Response) => {
  res.status(404).json({ error: "Endpoint not found" });
});

// Initialize and start server
async function startServer(): Promise<void> {
  try {
    await initializeOIDCClient();

    app.listen(PORT, () => {
      console.log(`Client Application running on port ${PORT}`);
      console.log(`Resource Server URL: ${RESOURCE_SERVER_URL}`);
      console.log(`Keycloak Issuer: ${keycloakIssuer.metadata.issuer}`);
    });
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

// Start the server
startServer();

export default app;
