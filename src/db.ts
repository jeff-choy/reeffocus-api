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

    -- Rooms changed shape (kind/schedule/nullable depth) and the old rows can't
    -- be migrated honestly — an old room has no agreed time to infer. Drop the
    -- old table once, on the first boot that sees the pre-'kind' schema. Guarded
    -- on the column's absence, so it is a no-op on every boot after that and
    -- never touches users, friendships or collections.
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM information_schema.tables
                  WHERE table_schema = 'public' AND table_name = 'rooms')
         AND NOT EXISTS (SELECT 1 FROM information_schema.columns
                          WHERE table_schema = 'public' AND table_name = 'rooms'
                            AND column_name = 'kind')
      THEN
        DROP TABLE rooms CASCADE;
      END IF;
    END $$;

    -- Two kinds of group dive:
    --   'room'       — everyone starts at the agreed time, each picks their own
    --                  length. Depth is NULL: it's per-diver.
    --   'expedition' — everyone commits to the same length for a bigger reward,
    --                  so depth is required.
    -- Scheduling is either 'daily' (start_min, minutes past local midnight, every
    -- day) or 'once' (start_at, an absolute instant). Storing the daily time as
    -- minutes-past-midnight rather than a timestamp keeps it local to each diver's
    -- clock — a 09:00 room is 09:00 wherever you are, which is what a habit means.
    CREATE TABLE IF NOT EXISTS rooms (
      id           TEXT PRIMARY KEY,
      name         TEXT NOT NULL,
      kind         TEXT NOT NULL DEFAULT 'room' CHECK (kind IN ('room','expedition')),
      depth        INTEGER CHECK (depth BETWEEN 10 AND 120),
      schedule     TEXT NOT NULL DEFAULT 'daily' CHECK (schedule IN ('daily','once')),
      start_min    INTEGER CHECK (start_min BETWEEN 0 AND 1439),
      start_at     TIMESTAMPTZ,
      host_id      TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
      -- An expedition without a depth is meaningless; a room with one is a lie.
      CHECK ((kind = 'expedition') = (depth IS NOT NULL)),
      -- Exactly one schedule field must be set, matching the schedule type.
      CHECK ((schedule = 'daily') = (start_min IS NOT NULL)),
      CHECK ((schedule = 'once')  = (start_at  IS NOT NULL))
    );

    -- Every finished group dive, for collective progression. Kept per-dive rather
    -- than as a running total so a room's depth/coral can be recomputed if the
    -- rules change, and so one device can't inflate a counter it owns.
    CREATE TABLE IF NOT EXISTS room_dives (
      id        TEXT PRIMARY KEY,
      room_id   TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      mins      INTEGER NOT NULL CHECK (mins > 0),
      depth     INTEGER NOT NULL CHECK (depth BETWEEN 10 AND 120),
      ts        TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS room_dives_room ON room_dives(room_id);

    CREATE TABLE IF NOT EXISTS room_members (
      room_id   TEXT NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
      user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (room_id, user_id)
    );

    -- Repair for a wound the 'kind' migration left behind: DROP TABLE rooms
    -- CASCADE also dropped room_members' and room_dives' room_id foreign keys,
    -- and CREATE TABLE IF NOT EXISTS never re-adds constraints to a table that
    -- already exists — so on databases that lived through that migration,
    -- deleting a room stranded its memberships and dives. Re-add the FKs under
    -- the same names Postgres gives the inline ones, so the guard is a no-op
    -- both on fresh databases and on every boot after the repair. NOT VALID
    -- because a handful of orphaned rows from the old dropped rooms table
    -- still exist and belong to real users — a boot-time migration shouldn't
    -- delete user data. NOT VALID skips only the scan of existing rows; the
    -- constraint (and its ON DELETE CASCADE) fully applies to everything new.
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints
                      WHERE table_schema = 'public' AND table_name = 'room_members'
                        AND constraint_name = 'room_members_room_id_fkey')
      THEN
        ALTER TABLE room_members
          ADD CONSTRAINT room_members_room_id_fkey
          FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE NOT VALID;
      END IF;
      IF NOT EXISTS (SELECT 1 FROM information_schema.table_constraints
                      WHERE table_schema = 'public' AND table_name = 'room_dives'
                        AND constraint_name = 'room_dives_room_id_fkey')
      THEN
        ALTER TABLE room_dives
          ADD CONSTRAINT room_dives_room_id_fkey
          FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE NOT VALID;
      END IF;
    END $$;

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

    -- Player reports, append-only — the app only ever inserts; moderation
    -- reads the table directly. Both FKs cascade: a report about (or from) a
    -- deleted account is meaningless without the account, and account deletion
    -- must not be blocked by moderation paperwork.
    CREATE TABLE IF NOT EXISTS reports (
      id          TEXT PRIMARY KEY,
      reporter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      target_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      reason      TEXT,
      created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    -- Diver names are how you tell each other apart when trading, so they must
    -- be unique — case-insensitively, so "Jeff" and "jeff" can't both exist.
    CREATE UNIQUE INDEX IF NOT EXISTS users_name_unique ON users (LOWER(name));

    -- Friendship is symmetric: adding someone stores both directions, so the
    -- lookup is a plain WHERE user_id = $1 with no OR across two columns.
    -- The CHECK stops a diver befriending themselves.
    CREATE TABLE IF NOT EXISTS friendships (
      user_id   TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      friend_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      since     TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, friend_id),
      CHECK (user_id <> friend_id)
    );

    -- Blocking. App Review Guideline 1.2 requires that a user be able to stop
    -- seeing, and being contacted by, another user. Deliberately one-directional
    -- in storage but enforced both ways at read time: if either side has blocked
    -- the other, neither appears to the other in divers, the leaderboard, rooms
    -- or trades. Storing one row per (blocker, blocked) keeps "unblock" a plain
    -- delete of the row the blocker created, without guessing who blocked whom.
    CREATE TABLE IF NOT EXISTS blocks (
      blocker_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      blocked_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      PRIMARY KEY (blocker_id, blocked_id),
      CHECK (blocker_id <> blocked_id)
    );
    -- The read-time filter looks up "did anyone block either of us", so the
    -- reverse direction needs its own index; the PK only covers blocker_id.
    CREATE INDEX IF NOT EXISTS blocks_blocked ON blocks(blocked_id);

    -- Added after launch, so they're ALTERs rather than part of the CREATEs:
    --   users.avatar_url   — dormant. Held uploaded profile photos during the
    --                        beta. Photos are not a v1 feature (unmoderated user
    --                        images shown to strangers is a Guideline 1.2
    --                        surface), so nothing writes or reads this now and
    --                        every diver renders as an initials tile. Kept only
    --                        so beta rows survive if photos return with
    --                        moderation behind them.
    --   user_stats.week_*  — this-week focus minutes, for a leaderboard that
    --                        resets every Monday for everyone. week_start is the
    --                        Monday the week_mins were accrued in; a stale
    --                        week_start reads as zero this week (see the board
    --                        query), so the reset needs no cron — it's implicit.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
    ALTER TABLE user_stats ADD COLUMN IF NOT EXISTS week_mins INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE user_stats ADD COLUMN IF NOT EXISTS week_start DATE;

    -- ── accounts ──────────────────────────────────────────────────────────
    -- Identity used to be the device id: users.id *was* the install's id, so a
    -- reinstall was a new person and a reef could not survive one. It is now an
    -- opaque uuid with credentials hanging off it, and the device is just a
    -- client holding a session token.
    --
    -- All three columns are nullable because not every account has every one:
    -- an email signup has no apple_sub, an Apple signup has no password_hash
    -- (and may have no email, if the user hid it).
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email         TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS apple_sub     TEXT;

    -- Case-insensitive uniqueness on the stored-lowercase column: the app
    -- normalises before writing, and this is the backstop that makes a race
    -- between two signups resolve to one account rather than two.
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (LOWER(email)) WHERE email IS NOT NULL;
    CREATE UNIQUE INDEX IF NOT EXISTS users_apple_sub_key ON users (apple_sub) WHERE apple_sub IS NOT NULL;

    -- Opaque session tokens, stored only as a SHA-256 hash. ON DELETE CASCADE
    -- is what makes "delete my account" also mean "log out everywhere", and it
    -- is why account deletion needs no extra step here.
    CREATE TABLE IF NOT EXISTS auth_sessions (
      token_hash TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      last_used  TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS auth_sessions_user ON auth_sessions(user_id);

    -- Null until the address is confirmed. A timestamp rather than a boolean
    -- because "when" answers questions "whether" can't — chiefly whether a
    -- verification predates an email change.
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified_at TIMESTAMPTZ;

    -- One row per outstanding verification link. The email is stored alongside
    -- the token rather than read from users at redemption time: it pins the
    -- link to the address it was sent to, so a link mailed to an old address
    -- cannot confirm a new one.
    CREATE TABLE IF NOT EXISTS email_verifications (
      token_hash TEXT PRIMARY KEY,
      user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      email      TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      expires_at TIMESTAMPTZ NOT NULL
    );
    CREATE INDEX IF NOT EXISTS email_verifications_user ON email_verifications(user_id);

    -- ── retire the device-id divers ───────────────────────────────────────
    -- Before accounts, users.id *was* the install's device id and there were no
    -- credentials at all. Those rows cannot be signed into by anyone, ever, and
    -- each one holds a unique diver name hostage — so a beta tester's abandoned
    -- "Jeff" would permanently block the real signup.
    --
    -- Safe to run on every boot, not just once: every account created since has
    -- at least one of these three set in the same INSERT that creates the row,
    -- so there is no window in which a live account looks like a legacy one.
    -- Everything else about a user cascades from here.
    DELETE FROM users
     WHERE password_hash IS NULL AND apple_sub IS NULL AND email IS NULL;
  `);
}

/**
 * Drop sessions that have aged out. Called opportunistically on login rather
 * than on a schedule: expired tokens are already rejected on use, so this is
 * housekeeping, not enforcement, and a cron for it would be a moving part
 * bought with nothing.
 */
export async function pruneExpiredSessions() {
  await query('DELETE FROM auth_sessions WHERE expires_at < now()');
  await query('DELETE FROM email_verifications WHERE expires_at < now()');
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
