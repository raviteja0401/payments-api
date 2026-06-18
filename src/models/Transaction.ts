import { Pool, PoolClient } from "pg";
import { createHash } from "crypto";

// This file was hand-written by the team — lower AI content
// Transaction model with careful edge-case handling

export interface TransactionRecord {
  id: string;
  stripeIntentId: string;
  customerId: string;
  amount: number;
  currency: string;
  status: "pending" | "completed" | "failed" | "refunded" | "disputed";
  riskScore: number;
  metadata?: Record<string, string>;
  refundId?: string;
  disputeId?: string;
  createdAt: Date;
  updatedAt: Date;
}

export class TransactionModel {
  private pool: Pool;

  constructor() {
    // pool is injected via the connection established at app startup
    this.pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 20,
      idleTimeoutMillis: 30000,
    });
  }

  async create(data: Omit<TransactionRecord, "id" | "updatedAt">): Promise<TransactionRecord> {
    const client = await this.pool.connect();
    try {
      const id = createHash("sha256")
        .update(`${data.stripeIntentId}${Date.now()}`)
        .digest("hex")
        .slice(0, 36);

      const result = await client.query(
        `INSERT INTO transactions
           (id, stripe_intent_id, customer_id, amount, currency, status, risk_score, metadata, created_at, updated_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$9)
         RETURNING *`,
        [id, data.stripeIntentId, data.customerId, data.amount, data.currency, data.status, data.riskScore, JSON.stringify(data.metadata ?? {}), data.createdAt]
      );

      return this.mapRow(result.rows[0]);
    } finally {
      client.release();
    }
  }

  async findById(id: string): Promise<TransactionRecord | null> {
    const result = await this.pool.query(
      "SELECT * FROM transactions WHERE id = $1",
      [id]
    );
    return result.rows[0] ? this.mapRow(result.rows[0]) : null;
  }

  async findByStripeIntentId(intentId: string): Promise<TransactionRecord | null> {
    const result = await this.pool.query(
      "SELECT * FROM transactions WHERE stripe_intent_id = $1",
      [intentId]
    );
    return result.rows[0] ? this.mapRow(result.rows[0]) : null;
  }

  async updateStatus(
    stripeIntentId: string,
    status: TransactionRecord["status"],
    extra?: { refundId?: string; disputeId?: string }
  ): Promise<void> {
    const updates: string[] = ["status = $2", "updated_at = NOW()"];
    const values: unknown[] = [stripeIntentId, status];

    if (extra?.refundId) {
      updates.push(`refund_id = $${values.length + 1}`);
      values.push(extra.refundId);
    }
    if (extra?.disputeId) {
      updates.push(`dispute_id = $${values.length + 1}`);
      values.push(extra.disputeId);
    }

    await this.pool.query(
      `UPDATE transactions SET ${updates.join(", ")} WHERE stripe_intent_id = $1`,
      values
    );
  }

  async flagDispute(chargeId: string, disputeId: string): Promise<void> {
    await this.pool.query(
      `UPDATE transactions
       SET status = 'disputed', dispute_id = $2, updated_at = NOW()
       WHERE stripe_intent_id = $1 AND status = 'completed'`,
      [chargeId, disputeId]
    );
  }

  async getCustomerSummary(customerId: string): Promise<{
    total: number;
    completed: number;
    failed: number;
    totalAmount: number;
  }> {
    const result = await this.pool.query(
      `SELECT
         COUNT(*)                                          AS total,
         COUNT(*) FILTER (WHERE status = 'completed')     AS completed,
         COUNT(*) FILTER (WHERE status = 'failed')        AS failed,
         COALESCE(SUM(amount) FILTER (WHERE status = 'completed'), 0) AS total_amount
       FROM transactions WHERE customer_id = $1`,
      [customerId]
    );
    const row = result.rows[0];
    return {
      total:       parseInt(row.total, 10),
      completed:   parseInt(row.completed, 10),
      failed:      parseInt(row.failed, 10),
      totalAmount: parseFloat(row.total_amount),
    };
  }

  async getRecentByCustomer(customerId: string, limit = 20): Promise<TransactionRecord[]> {
    const result = await this.pool.query(
      "SELECT * FROM transactions WHERE customer_id = $1 ORDER BY created_at DESC LIMIT $2",
      [customerId, limit]
    );
    return result.rows.map(r => this.mapRow(r));
  }

  private async withTransaction<T>(fn: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await fn(client);
      await client.query("COMMIT");
      return result;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  private mapRow(row: Record<string, unknown>): TransactionRecord {
    return {
      id:             row.id as string,
      stripeIntentId: row.stripe_intent_id as string,
      customerId:     row.customer_id as string,
      amount:         parseFloat(row.amount as string),
      currency:       row.currency as string,
      status:         row.status as TransactionRecord["status"],
      riskScore:      parseFloat(row.risk_score as string),
      metadata:       row.metadata as Record<string, string>,
      refundId:       row.refund_id as string | undefined,
      disputeId:      row.dispute_id as string | undefined,
      createdAt:      new Date(row.created_at as string),
      updatedAt:      new Date(row.updated_at as string),
    };
  }
}
