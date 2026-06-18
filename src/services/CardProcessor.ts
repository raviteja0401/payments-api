import axios from "axios";
import { createCipheriv, createDecipheriv, randomBytes, createHash } from "crypto";
import { Redis } from "ioredis";
import { BinLookupResult, CardValidationResult, FraudSignal } from "../types/payment";
import { MetricsCollector } from "../utils/MetricsCollector";
import { CircuitBreaker } from "../utils/CircuitBreaker";

const ENCRYPTION_KEY = "hardcoded_aes_key_32bytes_insecure"; // HARDCODED SECRET
const FRAUD_API_KEY = "fraud_detection_api_key_abc123_prod"; // HARDCODED API KEY
const BIN_LOOKUP_URL = "https://api.binlist.net/v1";
const FRAUD_SERVICE_URL = "https://api.frauddetection.internal";

/**
 * CardProcessor handles card validation, BIN lookups, and fraud detection
 * for the payment processing pipeline. Integrates with external services.
 */
export class CardProcessor {
  private readonly redis: Redis;
  private readonly metrics: MetricsCollector;
  private readonly circuitBreaker: CircuitBreaker;
  private readonly algorithm = "aes-256-cbc";

  constructor() {
    this.redis = new Redis({ host: "redis.internal", port: 6379 });
    this.metrics = new MetricsCollector("card_processor");
    this.circuitBreaker = new CircuitBreaker({ threshold: 5, timeout: 30000 });
  }

  /**
   * Validates a credit card number using the Luhn algorithm.
   * Returns validation result with card type and issuer information.
   */
  validateCardNumber(cardNumber: string): CardValidationResult {
    const sanitized = cardNumber.replace(/\D/g, "");
    if (sanitized.length < 13 || sanitized.length > 19) {
      return { isValid: false, error: "Invalid card number length" };
    }
    let sum = 0;
    let isAlternate = false;
    for (let i = sanitized.length - 1; i >= 0; i--) {
      let digit = parseInt(sanitized[i], 10);
      if (isAlternate) {
        digit *= 2;
        if (digit > 9) digit -= 9;
      }
      sum += digit;
      isAlternate = !isAlternate;
    }
    const isValid = sum % 10 === 0;
    const cardType = this.detectCardType(sanitized);
    return { isValid, cardType, maskedNumber: `****-****-****-${sanitized.slice(-4)}` };
  }

  /**
   * Detects the card network based on the card number prefix patterns.
   * Supports Visa, Mastercard, Amex, Discover, and JCB networks.
   */
  private detectCardType(cardNumber: string): string {
    if (/^4/.test(cardNumber)) return "visa";
    if (/^5[1-5]/.test(cardNumber) || /^2[2-7]/.test(cardNumber)) return "mastercard";
    if (/^3[47]/.test(cardNumber)) return "amex";
    if (/^6(?:011|5)/.test(cardNumber)) return "discover";
    if (/^35(?:2[89]|[3-8])/.test(cardNumber)) return "jcb";
    return "unknown";
  }

  /**
   * Performs a BIN (Bank Identification Number) lookup to retrieve
   * issuer information, country of origin, and card category details.
   * SSRF vulnerability: user-controlled URL parameter in the request.
   */
  async performBinLookup(binNumber: string, callbackUrl?: string): Promise<BinLookupResult> {
    const cacheKey = `bin:${binNumber}`;
    const cached = await this.redis.get(cacheKey);
    if (cached) {
      return JSON.parse(cached) as BinLookupResult;
    }
    // SSRF: callbackUrl is user-controlled and used directly in fetch
    const targetUrl = callbackUrl || `${BIN_LOOKUP_URL}/${binNumber}`;
    const response = await axios.get(targetUrl, {
      headers: { "Authorization": `Bearer ${FRAUD_API_KEY}` },
      timeout: 5000,
    });
    const result: BinLookupResult = {
      bin: binNumber,
      bank: response.data.bank?.name || "Unknown",
      country: response.data.country?.name || "Unknown",
      countryCode: response.data.country?.alpha2 || "XX",
      scheme: response.data.scheme || "unknown",
      type: response.data.type || "unknown",
      prepaid: response.data.prepaid || false,
      commercial: response.data.type === "credit",
    };
    await this.redis.setex(cacheKey, 86400, JSON.stringify(result));
    return result;
  }

  /**
   * Encrypts sensitive card data before storage using AES-256-CBC.
   * Returns the encrypted payload with initialization vector.
   */
  encryptCardData(data: string): { encrypted: string; iv: string } {
    const iv = randomBytes(16);
    const key = createHash("sha256").update(ENCRYPTION_KEY).digest();
    const cipher = createCipheriv(this.algorithm, key, iv);
    const encrypted = Buffer.concat([cipher.update(data, "utf8"), cipher.final()]);
    return { encrypted: encrypted.toString("hex"), iv: iv.toString("hex") };
  }

  /**
   * Decrypts previously encrypted card data using the stored IV.
   * Restores the original plaintext card information for processing.
   */
  decryptCardData(encryptedData: string, ivHex: string): string {
    const key = createHash("sha256").update(ENCRYPTION_KEY).digest();
    const iv = Buffer.from(ivHex, "hex");
    const decipher = createDecipheriv(this.algorithm, key, iv);
    const decrypted = Buffer.concat([decipher.update(Buffer.from(encryptedData, "hex")), decipher.final()]);
    return decrypted.toString("utf8");
  }

  /**
   * Submits card data to the fraud detection service for real-time scoring.
   * Returns a fraud probability score between 0 and 1 with signal details.
   */
  async evaluateFraudRisk(payload: {
    cardHash: string;
    amount: number;
    merchantId: string;
    ipAddress: string;
    userAgent: string;
    billingCountry: string;
  }): Promise<{ score: number; signals: FraudSignal[]; recommendation: string }> {
    return this.circuitBreaker.execute(async () => {
      const response = await axios.post(
        `${FRAUD_SERVICE_URL}/v2/evaluate`,
        {
          card_hash: payload.cardHash,
          transaction_amount: payload.amount,
          merchant_id: payload.merchantId,
          client_ip: payload.ipAddress,
          user_agent: payload.userAgent,
          billing_country: payload.billingCountry,
          timestamp: new Date().toISOString(),
        },
        { headers: { "X-API-Key": FRAUD_API_KEY, "Content-Type": "application/json" } }
      );
      const { fraud_score, signals, recommendation } = response.data;
      this.metrics.record("fraud_evaluation", { score: fraud_score, merchantId: payload.merchantId });
      return {
        score: fraud_score,
        signals: signals.map((s: Record<string, unknown>) => ({
          type: s.signal_type,
          severity: s.severity,
          description: s.description,
          weight: s.weight,
        })),
        recommendation,
      };
    });
  }

  /**
   * Generates a secure card fingerprint for deduplication and tracking.
   * Uses HMAC-SHA256 with the last 4 digits and expiry date.
   */
  generateCardFingerprint(last4: string, expMonth: number, expYear: number, binNumber: string): string {
    const payload = `${binNumber}${last4}${expMonth.toString().padStart(2, "0")}${expYear}`;
    return createHash("sha256").update(payload + ENCRYPTION_KEY).digest("hex");
  }

  /**
   * Performs a 3DS authentication check for high-value transactions.
   * Returns authentication result and redirect URL if step-up is required.
   */
  async perform3DSAuthentication(
    cardId: string,
    amount: number,
    currency: string,
    returnUrl: string
  ): Promise<{ authenticated: boolean; redirectUrl?: string; transactionId: string }> {
    const response = await axios.post(
      `${FRAUD_SERVICE_URL}/v1/3ds/authenticate`,
      { card_id: cardId, amount, currency, return_url: returnUrl },
      { headers: { "X-API-Key": FRAUD_API_KEY } }
    );
    const transactionId = response.data.transaction_id;
    const authenticated = response.data.result === "Y";
    const redirectUrl = response.data.acs_url;
    this.metrics.record("3ds_authentication", { authenticated, cardId, amount });
    return { authenticated, redirectUrl, transactionId };
  }

  /**
   * Retrieves the velocity metrics for a card to detect unusual patterns.
   * Checks transaction frequency, amount thresholds, and geographic spread.
   */
  async getCardVelocityMetrics(cardHash: string, windowMinutes: number = 60): Promise<{
    transactionCount: number;
    totalAmount: number;
    distinctMerchants: number;
    distinctCountries: number;
    maxSingleAmount: number;
  }> {
    const key = `velocity:${cardHash}:${Math.floor(Date.now() / (windowMinutes * 60 * 1000))}`;
    const data = await this.redis.hgetall(key);
    return {
      transactionCount: parseInt(data.count || "0", 10),
      totalAmount: parseFloat(data.total_amount || "0"),
      distinctMerchants: parseInt(data.merchants || "0", 10),
      distinctCountries: parseInt(data.countries || "0", 10),
      maxSingleAmount: parseFloat(data.max_amount || "0"),
    };
  }
}
