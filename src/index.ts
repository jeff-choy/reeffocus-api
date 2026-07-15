import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import 'dotenv/config';
import { query, tx, initSchema, collectionOf, addSpecies, pool } from './db.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 4000;

// ── identity ────────────────────────────────────────────────────────────────
// No passwords: each install generates a stable device id and sends it as a
// header. Enough to tell two real testers apart; swap for real auth later.
type User = { id: string; name: string; initial: string; avatar_bg: string; last_seen: string };

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

async function requireUser(req: Request, res: Response, next: NextFunction) {
  const id = req.header('x-device-id');
  if (!id) return res.status(401).json({ error: 'missing x-device-id' });
  const r = await query<User>('SELECT * FROM users WHERE id = $1', [id]);
  if (!r.rows[0]) return res.status(404).json({ error: 'unregistered device' });
  await query('UPDATE users SET last_seen = now() WHERE id = $1', [id]);
  req.user = r.rows[0];
  next();
}

const asyncRoute =
  (fn: (req: Request, res: Response) => Promise<any>) => (req: Request, res: Response, next: NextFunction) =>
    fn(req, res).catch(next);

const AVATARS = ['#9fd9d3', '#FFB5A7', '#FFD700', '#bfdde6', '#4FC3D9', '#4ADE80', '#FF8C69'];

app.get('/api/health', (_req, res) => res.json({ ok: true, service: 'reeffocus-api', time: Date.now() }));

/** First launch: claim a user row for this device. Idempotent. */
app.post(
  '/api/register',
  asyncRoute(async (req, res) => {
    const deviceId = String(req.body?.deviceId ?? '').trim();
    const rawName = String(req.body?.name ?? '').trim();
    if (!deviceId) return res.status(400).json({ error: 'deviceId required' });
    const name = (rawName || 'Diver').slice(0, 24);
    const initial = name[0].toUpperCase();
    const avatar = AVATARS[Math.abs([...deviceId].reduce((a, c) => a + c.charCodeAt(0), 0)) % AVATARS.length];

    await tx(async (c) => {
      await c.query(
        `INSERT INTO users (id, name, initial, avatar_bg) VALUES ($1, $2, $3, $4)
         ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, initial = EXCLUDED.initial, last_seen = now()`,
        [deviceId, name, initial, avatar]
      );
      await c.query('INSERT INTO user_stats (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [deviceId]);
    });

    const u = await query<User>('SELECT * FROM users WHERE id = $1', [deviceId]);
    res.json({ user: u.rows[0], collection: await collectionOf(deviceId) });
  })
);

app.get(
  '/api/me',
  requireUser,
  asyncRoute(async (req, res) => {
    const stats = await query('SELECT * FROM user_stats WHERE user_id = $1', [req.user!.id]);
    res.json({ user: req.user, collection: await collectionOf(req.user!.id), stats: stats.rows[0] ?? null });
  })
);

/** Record a finished dive. The server owns the collection so trades are honest. */
app.post(
  '/api/me/catch',
  requireUser,
  asyncRoute(async (req, res) => {
    const speciesId = req.body?.speciesId ? String(req.body.speciesId) : null;
    const mins = Math.max(0, Math.min(120, Number(req.body?.mins) || 0));
    const me = req.user!.id;

    await tx(async (c) => {
      if (speciesId) await addSpecies(c, me, speciesId, 1);
      await c.query(
        `UPDATE user_stats
            SET total_mins = total_mins + $2,
                dives = dives + 1,
                caught = caught + $3,
                updated_at = now()
          WHERE user_id = $1`,
        [me, mins, speciesId ? 1 : 0]
      );
    });

    const stats = await query('SELECT * FROM user_stats WHERE user_id = $1', [me]);
    res.json({ collection: await collectionOf(me), stats: stats.rows[0] });
  })
);

/** Everyone else on this server — the beta's "friends" list. */
app.get(
  '/api/divers',
  requireUser,
  asyncRoute(async (req, res) => {
    const r = await query(
      `SELECT u.id, u.name, u.initial, u.avatar_bg, u.last_seen,
              COALESCE(s.total_mins,0) AS total_mins,
              COALESCE(s.dives,0) AS dives,
              COALESCE(ARRAY_AGG(sp.species_id) FILTER (WHERE sp.count > 0), '{}') AS species,
              -- only spares are offerable, so the app can show what's actually gettable
              COALESCE(ARRAY_AGG(sp.species_id) FILTER (WHERE sp.count > 1), '{}') AS spares
         FROM users u
         LEFT JOIN user_stats s ON s.user_id = u.id
         LEFT JOIN user_species sp ON sp.user_id = u.id
        WHERE u.id <> $1
        GROUP BY u.id, s.total_mins, s.dives
        ORDER BY u.last_seen DESC`,
      [req.user!.id]
    );
    res.json(r.rows.map(shapeDiver));
  })
);

function shapeDiver(x: any) {
  const idleMs = Date.now() - new Date(x.last_seen).getTime();
  const active = idleMs < 5 * 60_000;
  return {
    id: x.id,
    name: x.name,
    initial: x.initial,
    avatarBg: x.avatar_bg,
    species: x.species ?? [],
    spares: x.spares ?? [],
    totalHours: Math.floor(Number(x.total_mins) / 60),
    dives: Number(x.dives),
    status: active ? 'Active now' : `Last seen ${relTime(idleMs)}`,
    statusFg: active ? '#1e8a4a' : '#5b7484',
    statusColor: active ? '#4ADE80' : '#b9cdd8',
    today: `${Math.floor(Number(x.total_mins) / 60)}h ${Number(x.total_mins) % 60}m`,
  };
}

function relTime(ms: number) {
  const m = Math.floor(ms / 60000);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

app.get(
  '/api/leaderboard',
  requireUser,
  asyncRoute(async (req, res) => {
    const r = await query(
      `SELECT u.id, u.name, u.initial, u.avatar_bg, COALESCE(s.total_mins,0) AS total_mins
         FROM users u LEFT JOIN user_stats s ON s.user_id = u.id
        ORDER BY total_mins DESC LIMIT 25`,
      []
    );
    const medal = ['#FFD700', '#8fa8b5', '#c98b4a'];
    res.json(
      r.rows.map((x: any, i: number) => ({
        rank: String(i + 1),
        name: x.id === req.user!.id ? `${x.name} (you)` : x.name,
        initial: x.initial,
        avatarBg: x.avatar_bg,
        time: `${Math.floor(Number(x.total_mins) / 60)}h ${Number(x.total_mins) % 60}m`,
        rankFg: medal[i] ?? '#8fa8b5',
        you: x.id === req.user!.id,
      }))
    );
  })
);

// ── rooms ───────────────────────────────────────────────────────────────────
async function roomsWithMembers() {
  const r = await query(
    `SELECT r.id, r.name, r.depth, h.name AS host,
            COALESCE(JSON_AGG(JSON_BUILD_OBJECT('id', u.id, 'initial', u.initial, 'bg', u.avatar_bg))
                     FILTER (WHERE u.id IS NOT NULL), '[]') AS participants
       FROM rooms r
       JOIN users h ON h.id = r.host_id
       LEFT JOIN room_members m ON m.room_id = r.id
       LEFT JOIN users u ON u.id = m.user_id
      GROUP BY r.id, h.name
      ORDER BY r.created_at DESC`
  );
  return r.rows.map((x: any) => ({ ...x, depth: Number(x.depth), minutesLeft: Number(x.depth) }));
}

app.get('/api/rooms', requireUser, asyncRoute(async (_req, res) => res.json(await roomsWithMembers())));

app.post(
  '/api/rooms',
  requireUser,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name ?? '').trim();
    const depth = Number(req.body?.depth);
    if (!name) return res.status(400).json({ error: 'name required' });
    if (!Number.isFinite(depth) || depth < 1 || depth > 120) return res.status(400).json({ error: 'depth must be 1-120' });
    const id = 'r' + randomUUID().slice(0, 8);
    await tx(async (c) => {
      await c.query('INSERT INTO rooms (id, name, depth, host_id) VALUES ($1,$2,$3,$4)', [id, name, Math.round(depth), req.user!.id]);
      await c.query('INSERT INTO room_members (room_id, user_id) VALUES ($1,$2)', [id, req.user!.id]);
    });
    res.status(201).json((await roomsWithMembers()).find((r: any) => r.id === id));
  })
);

app.post(
  '/api/rooms/:id/join',
  requireUser,
  asyncRoute(async (req, res) => {
    const r = await query('SELECT 1 FROM rooms WHERE id = $1', [req.params.id]);
    if (!r.rows[0]) return res.status(404).json({ error: 'no such room' });
    await query('INSERT INTO room_members (room_id, user_id) VALUES ($1,$2) ON CONFLICT DO NOTHING', [req.params.id, req.user!.id]);
    res.json((await roomsWithMembers()).find((x: any) => x.id === req.params.id));
  })
);

app.post(
  '/api/rooms/:id/leave',
  requireUser,
  asyncRoute(async (req, res) => {
    await query('DELETE FROM room_members WHERE room_id = $1 AND user_id = $2', [req.params.id, req.user!.id]);
    res.json((await roomsWithMembers()).find((x: any) => x.id === req.params.id) ?? { id: req.params.id, removed: true });
  })
);

// ── trading (offer → accept) ────────────────────────────────────────────────
async function tradesFor(userId: string) {
  const r = await query(
    `SELECT t.*, uf.name AS from_name, uf.initial AS from_initial, uf.avatar_bg AS from_bg,
            ut.name AS to_name, ut.initial AS to_initial, ut.avatar_bg AS to_bg
       FROM trades t
       JOIN users uf ON uf.id = t.from_id
       JOIN users ut ON ut.id = t.to_id
      WHERE (t.from_id = $1 OR t.to_id = $1) AND t.status = 'pending'
      ORDER BY t.created_at DESC`,
    [userId]
  );
  return {
    incoming: r.rows.filter((x: any) => x.to_id === userId).map(shapeTrade),
    outgoing: r.rows.filter((x: any) => x.from_id === userId).map(shapeTrade),
  };
}

const shapeTrade = (x: any) => ({
  id: x.id,
  fromId: x.from_id,
  toId: x.to_id,
  fromName: x.from_name,
  fromInitial: x.from_initial,
  fromBg: x.from_bg,
  toName: x.to_name,
  giveId: x.give_id,
  getId: x.get_id,
  status: x.status,
  createdAt: x.created_at,
});

app.get('/api/trades', requireUser, asyncRoute(async (req, res) => res.json(await tradesFor(req.user!.id))));

/** Propose: I give `giveId`, I want `getId` from you. Nothing moves yet. */
app.post(
  '/api/trades',
  requireUser,
  asyncRoute(async (req, res) => {
    const me = req.user!.id;
    const toId = String(req.body?.toId ?? '');
    const giveId = String(req.body?.giveId ?? '');
    const getId = String(req.body?.getId ?? '');
    if (!toId || !giveId || !getId) return res.status(400).json({ error: 'toId, giveId, getId required' });
    if (toId === me) return res.status(400).json({ error: 'cannot trade with yourself' });

    const mine = await collectionOf(me);
    const theirs = await collectionOf(toId);
    if ((mine[giveId] ?? 0) < 2) return res.status(400).json({ error: 'you need a spare of that species to offer it' });
    if ((theirs[getId] ?? 0) < 2) return res.status(400).json({ error: 'they only have one of that — they can’t spare it' });

    const id = 't' + randomUUID().slice(0, 8);
    await query('INSERT INTO trades (id, from_id, to_id, give_id, get_id) VALUES ($1,$2,$3,$4,$5)', [id, me, toId, giveId, getId]);
    res.status(201).json(await tradesFor(me));
  })
);

/** Accept: the swap happens here, atomically, and only with both sides' consent. */
app.post(
  '/api/trades/:id/accept',
  requireUser,
  asyncRoute(async (req, res) => {
    const me = req.user!.id;
    const out = await tx(async (c) => {
      const t = await c.query(`SELECT * FROM trades WHERE id = $1 AND status = 'pending' FOR UPDATE`, [req.params.id]);
      const trade = t.rows[0];
      if (!trade) throw Object.assign(new Error('no such pending trade'), { status: 404 });
      if (trade.to_id !== me) throw Object.assign(new Error('only the recipient can accept'), { status: 403 });

      // re-check both sides inside the transaction: stock may have changed
      const a = await c.query('SELECT count FROM user_species WHERE user_id=$1 AND species_id=$2', [trade.from_id, trade.give_id]);
      const b = await c.query('SELECT count FROM user_species WHERE user_id=$1 AND species_id=$2', [trade.to_id, trade.get_id]);
      if ((a.rows[0]?.count ?? 0) < 2) throw Object.assign(new Error('they no longer have a spare'), { status: 409 });
      if ((b.rows[0]?.count ?? 0) < 2) throw Object.assign(new Error('you no longer have a spare'), { status: 409 });

      await addSpecies(c, trade.from_id, trade.give_id, -1);
      await addSpecies(c, trade.to_id, trade.give_id, +1);
      await addSpecies(c, trade.to_id, trade.get_id, -1);
      await addSpecies(c, trade.from_id, trade.get_id, +1);
      await c.query(`UPDATE trades SET status='accepted', resolved_at=now() WHERE id=$1`, [trade.id]);
      return trade;
    });
    res.json({ ok: true, trade: shapeTrade(out), collection: await collectionOf(me) });
  })
);

app.post(
  '/api/trades/:id/decline',
  requireUser,
  asyncRoute(async (req, res) => {
    const r = await query(
      `UPDATE trades SET status='declined', resolved_at=now()
        WHERE id=$1 AND status='pending' AND (to_id=$2 OR from_id=$2) RETURNING id`,
      [req.params.id, req.user!.id]
    );
    if (!r.rows[0]) return res.status(404).json({ error: 'no such pending trade' });
    res.json(await tradesFor(req.user!.id));
  })
);

// ── ocean impact (shared across the club) ───────────────────────────────────
app.get(
  '/api/impact/community',
  asyncRoute(async (_req, res) => {
    const r = await query(`SELECT COALESCE(SUM(total_mins),0) AS mins FROM user_stats`);
    const pearls = 18442 + Number(r.rows[0].mins) * 2;
    res.json({ corals: Math.max(2, Math.floor(pearls / 500) - 34), communityPearls: pearls });
  })
);

app.get('/api/ocean-fact', (_req, res) => {
  const apiKey = process.env.OCEAN_API_KEY;
  res.json({
    fact: 'Coral reefs cover under 1% of the ocean floor but support about 25% of all marine species.',
    source: apiKey ? 'keyed-proxy' : 'static',
  });
});

// ── errors ──────────────────────────────────────────────────────────────────
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err?.status ?? 500;
  if (status >= 500) console.error('[reeffocus-api]', err);
  res.status(status).json({ error: err?.message ?? 'server error' });
});

initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`ReefFocus API listening on http://0.0.0.0:${PORT}`));
  })
  .catch((e) => {
    console.error('[reeffocus-api] failed to init schema:', e.message);
    process.exit(1);
  });

process.on('SIGTERM', () => pool.end().then(() => process.exit(0)));
