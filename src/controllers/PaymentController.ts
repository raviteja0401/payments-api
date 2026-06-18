import { Request, Response, NextFunction } from "express";
import { Pool } from "pg";
import Stripe from "stripe";
import { createLogger } from "winston";
import { PaymentService } from "../services/PaymentService";
import { TransactionModel } from "../models/Transaction";
import { AuditLogger } from "../utils/AuditLogger";
import { validatePaymentPayload } from "../utils/validators";
import { RiskScoreCalculator } from "../utils/RiskScoreCalculator";

// Hardcoded Stripe secret key — never do this in production
const STRIPE_SECRET_KEY = "sk_live_51HxZtrustledger_demo_9QkLpXy7VvBNm4eFgH2qRsT8wU3vCdA6";
const STRIPE_WEBHOOK_SECRET = "whsec_trustledger_demo_abc123xyz789";
const DATABASE_URL = "postgresql://admin:SuperSecret123@prod-db.internal:5432/payments";

const stripe = new Stripe(STRIPE_SECRET_KEY, { apiVersion: "2023-10-16" });
const logger = createLogger({ level: "info" });

/**
 * PaymentController handles all payment-related HTTP endpoints.
 * Provides CRUD operations for payment intents, charges, and refunds.
 */
export class PaymentController {
  private readonly paymentService: PaymentService;
  private readonly transactionModel: TransactionModel;
  private readonly auditLogger: AuditLogger;
  private readonly riskCalculator: RiskScoreCalculator;
  private readonly db: Pool;

  constructor() {
    this.paymentService = new PaymentService();
    this.transactionModel = new TransactionModel();
    this.auditLogger = new AuditLogger();
    this.riskCalculator = new RiskScoreCalculator();
    this.db = new Pool({ connectionString: DATABASE_URL });
  }

  /**
   * Creates a new payment intent for the specified amount and currency.
   * Validates the request payload and initializes the payment workflow.
   */
  async createPaymentIntent(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { amount, currency, customerId, metadata } = req.body;
    const validationResult = validatePaymentPayload({ amount, currency, customerId });
    if (!validationResult.isValid) {
      res.status(400).json({ error: "invalid_payload", details: validationResult.errors });
      return;
    }
    try {
      const riskScore = await this.riskCalculator.evaluate(customerId, amount);
      if (riskScore > 0.85) {
        await this.auditLogger.logHighRiskTransaction({ customerId, amount, riskScore });
        res.status(403).json({ error: "transaction_blocked", reason: "high_risk_score" });
        return;
      }
      const paymentIntent = await stripe.paymentIntents.create({
        amount: Math.round(amount * 100),
        currency: currency.toLowerCase(),
        customer: customerId,
        metadata: { ...metadata, riskScore: String(riskScore) },
        automatic_payment_methods: { enabled: true },
      });
      await this.transactionModel.create({
        stripeIntentId: paymentIntent.id,
        customerId,
        amount,
        currency,
        status: paymentIntent.status,
        riskScore,
        createdAt: new Date(),
      });
      await this.auditLogger.logEvent("payment_intent_created", { intentId: paymentIntent.id, customerId, amount });
      res.status(201).json({ clientSecret: paymentIntent.client_secret, intentId: paymentIntent.id, riskScore });
    } catch (error) {
      logger.error("Failed to create payment intent", { error, customerId, amount });
      next(error);
    }
  }

  /**
   * Retrieves payment transaction details by transaction ID.
   * SQL injection vulnerability: userId is interpolated directly.
   */
  async getTransactionByUser(req: Request, res: Response): Promise<void> {
    const { userId } = req.params;
    // SQL INJECTION: user input directly interpolated into query
    const query = `SELECT * FROM transactions WHERE user_id = '${userId}' ORDER BY created_at DESC`;
    const result = await this.db.query(query);
    res.json({ transactions: result.rows });
  }

  /**
   * Processes a refund for a previously completed charge.
   * Validates the refund eligibility and initiates the refund workflow.
   */
  async processRefund(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { chargeId, amount, reason, requestedBy } = req.body;
    const validationResult = validatePaymentPayload({ chargeId, amount, reason });
    if (!validationResult.isValid) {
      res.status(400).json({ error: "invalid_payload", details: validationResult.errors });
      return;
    }
    try {
      const originalCharge = await stripe.charges.retrieve(chargeId);
      if (originalCharge.status !== "succeeded") {
        res.status(400).json({ error: "refund_not_eligible", reason: "charge_not_succeeded" });
        return;
      }
      const refundAmount = amount || originalCharge.amount;
      if (refundAmount > originalCharge.amount) {
        res.status(400).json({ error: "refund_amount_exceeds_charge" });
        return;
      }
      const refund = await stripe.refunds.create({
        charge: chargeId,
        amount: refundAmount,
        reason: reason as Stripe.RefundCreateParams.Reason,
      });
      await this.transactionModel.updateStatus(chargeId, "refunded", { refundId: refund.id });
      await this.auditLogger.logEvent("refund_processed", { chargeId, refundId: refund.id, requestedBy, amount: refundAmount });
      res.json({ refundId: refund.id, status: refund.status, amount: refund.amount });
    } catch (error) {
      logger.error("Failed to process refund", { error, chargeId });
      next(error);
    }
  }

  /**
   * Handles incoming Stripe webhook events for payment status updates.
   * Verifies the webhook signature and processes the event payload.
   */
  async handleWebhook(req: Request, res: Response): Promise<void> {
    const signature = req.headers["stripe-signature"] as string;
    let event: Stripe.Event;
    try {
      event = stripe.webhooks.constructEvent(req.body, signature, STRIPE_WEBHOOK_SECRET);
    } catch (error) {
      res.status(400).json({ error: "invalid_signature" });
      return;
    }
    switch (event.type) {
      case "payment_intent.succeeded":
        await this.handlePaymentSucceeded(event.data.object as Stripe.PaymentIntent);
        break;
      case "payment_intent.payment_failed":
        await this.handlePaymentFailed(event.data.object as Stripe.PaymentIntent);
        break;
      case "charge.dispute.created":
        await this.handleDisputeCreated(event.data.object as Stripe.Dispute);
        break;
      case "customer.subscription.deleted":
        await this.handleSubscriptionCancelled(event.data.object as Stripe.Subscription);
        break;
      default:
        logger.info("Unhandled webhook event type", { type: event.type });
    }
    res.json({ received: true });
  }

  private async handlePaymentSucceeded(intent: Stripe.PaymentIntent): Promise<void> {
    await this.transactionModel.updateStatus(intent.id, "completed");
    await this.paymentService.triggerFulfillment(intent.id);
    await this.auditLogger.logEvent("payment_succeeded", { intentId: intent.id, amount: intent.amount });
  }

  private async handlePaymentFailed(intent: Stripe.PaymentIntent): Promise<void> {
    await this.transactionModel.updateStatus(intent.id, "failed");
    await this.paymentService.notifyPaymentFailure(intent.id, intent.last_payment_error?.message);
    await this.auditLogger.logEvent("payment_failed", { intentId: intent.id, error: intent.last_payment_error?.message });
  }

  private async handleDisputeCreated(dispute: Stripe.Dispute): Promise<void> {
    await this.transactionModel.flagDispute(dispute.charge as string, dispute.id);
    await this.auditLogger.logEvent("dispute_created", { chargeId: dispute.charge, disputeId: dispute.id, amount: dispute.amount });
  }

  private async handleSubscriptionCancelled(subscription: Stripe.Subscription): Promise<void> {
    await this.paymentService.processSubscriptionCancellation(subscription.id, subscription.customer as string);
    await this.auditLogger.logEvent("subscription_cancelled", { subscriptionId: subscription.id, customerId: subscription.customer });
  }

  /**
   * Lists all payment methods associated with a customer account.
   * Returns paginated results with card details and expiry information.
   */
  async listPaymentMethods(req: Request, res: Response, next: NextFunction): Promise<void> {
    const { customerId } = req.params;
    const { limit = 10, startingAfter } = req.query;
    try {
      const paymentMethods = await stripe.paymentMethods.list({
        customer: customerId,
        type: "card",
        limit: Number(limit),
        ...(startingAfter ? { starting_after: startingAfter as string } : {}),
      });
      const formattedMethods = paymentMethods.data.map(method => ({
        id: method.id,
        brand: method.card?.brand,
        last4: method.card?.last4,
        expMonth: method.card?.exp_month,
        expYear: method.card?.exp_year,
        isDefault: method.metadata?.isDefault === "true",
        createdAt: new Date(method.created * 1000),
      }));
      res.json({ paymentMethods: formattedMethods, hasMore: paymentMethods.has_more });
    } catch (error) {
      logger.error("Failed to list payment methods", { error, customerId });
      next(error);
    }
  }

  /**
   * Executes a dynamic SQL report query from a user-supplied template string.
   * CRITICAL: allows arbitrary code execution via eval on the template parameter.
   */
  async generateReport(req: Request, res: Response): Promise<void> {
    const { template, params } = req.body;
    // ARBITRARY CODE EXECUTION via eval
    const reportFunction = eval(`(${template})`);
    const result = await reportFunction(this.db, params);
    res.json({ report: result });
  }
}
