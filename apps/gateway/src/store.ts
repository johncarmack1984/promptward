// Event store. The eval and dashboard never require a database -- the in-memory
// store is the default; Postgres is used when DATABASE_URL is set.
import type { RequestRecord, StoreStats } from "./types.js";

export interface EventStore {
  record(r: RequestRecord): Promise<void>;
  list(limit?: number): Promise<RequestRecord[]>;
  stats(): Promise<StoreStats>;
  close(): Promise<void>;
}

function computeStats(rows: RequestRecord[]): StoreStats {
  return {
    count: rows.length,
    totalCostUsd: rows.reduce((s, r) => s + (r.costUsd ?? 0), 0),
    blocked: rows.filter((r) => r.blocked).length,
    findings: rows.reduce((s, r) => s + r.inboundFindings.length + r.outboundFindings.length, 0),
  };
}

export class InMemoryStore implements EventStore {
  private rows: RequestRecord[] = [];

  async record(r: RequestRecord): Promise<void> {
    this.rows.push(r);
  }

  async list(limit = 100): Promise<RequestRecord[]> {
    return this.rows.slice(-limit).reverse();
  }

  async stats(): Promise<StoreStats> {
    return computeStats(this.rows);
  }

  async close(): Promise<void> {}
}

/**
 * Postgres-backed store. Lazily imports `pg` so the in-memory path has no
 * dependency on a database driver being installed/available.
 */
export class PgStore implements EventStore {
  private constructor(private pool: import("pg").Pool) {}

  static async connect(databaseUrl: string): Promise<PgStore> {
    const { Pool } = await import("pg");
    const pool = new Pool({ connectionString: databaseUrl });
    await pool.query(`
      CREATE TABLE IF NOT EXISTS requests (
        id            TEXT PRIMARY KEY,
        ts            TIMESTAMPTZ NOT NULL,
        provider      TEXT NOT NULL,
        model         TEXT NOT NULL,
        action        TEXT NOT NULL,
        inbound       JSONB NOT NULL,
        outbound      JSONB NOT NULL,
        input_tokens  INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        cost_usd      DOUBLE PRECISION,
        latency_ms    DOUBLE PRECISION NOT NULL,
        blocked       BOOLEAN NOT NULL,
        record        JSONB NOT NULL
      )
    `);
    return new PgStore(pool);
  }

  async record(r: RequestRecord): Promise<void> {
    await this.pool.query(
      `INSERT INTO requests (id, ts, provider, model, action, inbound, outbound,
         input_tokens, output_tokens, cost_usd, latency_ms, blocked, record)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       ON CONFLICT (id) DO NOTHING`,
      [
        r.id,
        r.ts,
        r.provider,
        r.model,
        r.action,
        JSON.stringify(r.inboundFindings),
        JSON.stringify(r.outboundFindings),
        r.inputTokens,
        r.outputTokens,
        r.costUsd,
        r.latencyMs,
        r.blocked,
        JSON.stringify(r),
      ],
    );
  }

  async list(limit = 100): Promise<RequestRecord[]> {
    const res = await this.pool.query<{ record: RequestRecord }>(
      `SELECT record FROM requests ORDER BY ts DESC LIMIT $1`,
      [limit],
    );
    return res.rows.map((row) => row.record);
  }

  async stats(): Promise<StoreStats> {
    return computeStats(await this.list(10_000));
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

export async function makeStore(databaseUrl: string | null): Promise<EventStore> {
  if (databaseUrl) return PgStore.connect(databaseUrl);
  return new InMemoryStore();
}
