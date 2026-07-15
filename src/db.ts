import pg from 'pg';

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  console.error(
    '[reeffocus-api] DATABASE_URL is not set. Point it at your Postgres, e.g.\n' +
      '  local:  postgres://reef:reef@localhost:5440/reef\n' +
      '  hosted: the connection string from Neon / Render / Supabase'
  );
  process.exit(1);
}

// Hosted Postgres (Neon, Render, Supabase) terminates TLS with certs Node won't
// verify by default; local Docker has no TLS at all.
const isLocal = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL);

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: isLocal ? undefined : { rejectUnauthorized: false },
  max: 5,
});

export async function query<T extends pg.QueryResultRow = any>(text: string, params: any[] = []) {
  return pool.query<T>(text, params);
}

/** Run fn inside a transaction; rolls back on throw. Used for the trade swap. */
export async function tx<T>(fn: (c: pg.PoolClient) => Promise<T>): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const out = await fn(client);
    await client.query('COMMIT');
    return out;
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}

/**
 * Idempotent schema. Runs on every boot — fine at this size and means a fresh
 * database (or a new host) needs no separate migration step.
 */
export async function initSchema() {
  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      initial     TEXT NOT NULL,
      avatar_bg   TEXT NOT NULL,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_seen   TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS user_species (
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      species_id TEXT NOT NULL,
      count      INTEGER NOT NULL DEFAULT 0 CHECK (count >= 0),
      PRIMARY KEY (user_id, species_id)
    );

    CREATE TABLE IF NOT EXISTS user_stats (
      user_id    TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      total_mins INTEGER NOT NULL DEFAULT 0,
      dives      INTEGER NOT NULL DEFAULT 0,
      caught     INTEGER NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS rooms (
      id         TEXT PRIMARY KEY,
      name       TEXT NOT NULL,
      depth      INTEGER NOT NULL CHECK (depth BETWEEN 1 AND 120),
      host_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE TABLE IF NOT EXISTS room_members (
      room_id   TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (room_id, user_id)
    );

    -- A trade is an offer until the other side accepts. Nobody's fish moves
    -- without consent.
    CREATE TABLE IF NOT EXISTS trades (
      id          TEXT PRIMARY KEY,
      from_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      to_id       TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      give_id     TEXT NOT NULL,
      get_id      TEXT NOT NULL,
      status      TEXT NOT NULL DEFAULT 'pending',
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
      resolved_at TIMESTAMPTZ
    );

    CREATE INDEX IF NOT EXISTS trades_to_status ON trades(to_id, status);
    CREATE INDEX IF NOT EXISTS trades_from_status ON trades(from_id, status);

    -- Diver names are how you tell each other apart when trading, so they must
    -- be unique — case-insensitively, so "Jeff" and "jeff" can't both exist.
    CREATE UNIQUE INDEX IF NOT EXISTS users_name_unique ON users (LOWER(name));
  `);
}

export async function addSpecies(client: pg.PoolClient, userId: string, speciesId: string, delta: number) {
  if (delta < 0) {
    // Must be a plain UPDATE, not an upsert: Postgres checks CHECK (count >= 0)
    // against the *proposed* INSERT row before ON CONFLICT can resolve, so an
    // upsert of -1 fails the constraint even when the row already exists.
    // The CHECK still protects us here — it rejects any update that would go
    // below zero, which is exactly the guard we want on a trade.
    const r = await client.query(
      `UPDATE user_species SET count = count + $3
        WHERE user_id = $1 AND species_id = $2
        RETURNING count`,
      [userId, speciesId, delta]
    );
    if (!r.rows[0]) throw Object.assign(new Error('species not held'), { status: 409 });
    return;
  }
  await client.query(
    `INSERT INTO user_species (user_id, species_id, count)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, species_id)
     DO UPDATE SET count = user_species.count + $3`,
    [userId, speciesId, delta]
  );
}

export async function collectionOf(userId: string): Promise<Record<string, number>> {
  const r = await query<{ species_id: string; count: number }>(
    'SELECT species_id, count FROM user_species WHERE user_id = $1 AND count > 0',
    [userId]
  );
  return Object.fromEntries(r.rows.map((x) => [x.species_id, Number(x.count)]));
}
