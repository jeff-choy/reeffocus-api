import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import 'dotenv/config';
import { query, tx, initSchema, collectionOf, addSpecies, pool, pruneExpiredSessions } from './db.js';
import { isProfaneName } from './moderation.js';
import {
  VERIFY_HOURS,
  bearerToken,
  hashPassword,
  hashToken,
  newSession,
  newVerification,
  normaliseEmail,
  validateEmail,
  validatePassword,
  verifyPassword,
} from './auth.js';
import { canSendMail, mailConfigured, sendMail, verificationEmail } from './mail.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = Number(process.env.PORT) || 4000;

// ── rate limiting ───────────────────────────────────────────────────────────
// The host's proxy terminates TLS in front of us; trust exactly one hop so the
// limiter's IP fallback keys on the real client, not the proxy's own address.
app.set('trust proxy', 1);

// Keyed by device id — the app's identity — so one abusive install can't hide
// behind a shared NAT IP (a dorm, an office) and get everyone else throttled.
// IP is the fallback for traffic that predates registration.
const limitKey = (req: Request) => req.header('x-device-id') ?? ipKeyGenerator(req.ip ?? '');
const LIMIT_WINDOW_MS = 15 * 60 * 1000;
// Same `{ error }` shape as every other API error, so clients need no special case.
const LIMIT_MESSAGE = { error: 'Too many requests — slow down and try again in a bit.' };

const globalLimiter = rateLimit({
  windowMs: LIMIT_WINDOW_MS,
  limit: 300,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  message: LIMIT_MESSAGE,
  // Health stays unthrottled: uptime monitors poll it on their own schedule
  // and a 429 there would page us for a limiter, not an outage.
  skip: (req) => req.path === '/api/health',
});
app.use(globalLimiter);

// Registration, name probing and friend-adding are the abuse-shaped endpoints
// (name enumeration, signup floods, spam adds), so they get a far tighter
// budget than normal app traffic ever needs.
const strictLimiter = rateLimit({
  windowMs: LIMIT_WINDOW_MS,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: limitKey,
  message: LIMIT_MESSAGE,
});

// ── identity ────────────────────────────────────────────────────────────────
// Identity is an account, not an install. It used to be the device id: the
// client sent `x-device-id` and that string *was* users.id, which meant a
// reinstall was a new person and there was no way back to your reef. Now the
// client signs in and sends `Authorization: Bearer <session token>`.
//
// The device-id header still exists, but only as a rate-limiting key on the
// unauthenticated endpoints. It grants nothing.
type User = {
  id: string;
  name: string;
  initial: string;
  avatar_bg: string;
  avatar_url: string | null;
  email: string | null;
  email_verified_at: string | null;
  last_seen: string;
};

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      user?: User;
      sessionTokenHash?: string;
    }
  }
}

/**
 * Every column of `users` that is safe to hand to a client. Explicit, not
 * `SELECT *`: the moment password_hash and apple_sub joined this table, a
 * wildcard select feeding `res.json({ user })` became a credential leak.
 */
const USER_COLS = 'id, name, initial, avatar_bg, avatar_url, email, email_verified_at, last_seen';

async function requireUser(req: Request, res: Response, next: NextFunction) {
  const token = bearerToken(req.header('authorization'));
  if (!token) return res.status(401).json({ error: 'Sign in to continue.' });

  const tokenHash = hashToken(token);
  // One round trip, and the expiry is enforced in the join rather than in JS —
  // so an expired token is indistinguishable from a forged one from here.
  const r = await query<User>(
    `SELECT ${USER_COLS.split(', ').map((c) => `u.${c}`).join(', ')}
       FROM auth_sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.expires_at > now()`,
    [tokenHash]
  );
  if (!r.rows[0]) return res.status(401).json({ error: 'Your session has expired. Sign in again.' });

  // Best-effort liveness bookkeeping; never blocks the request.
  void query('UPDATE auth_sessions SET last_used = now() WHERE token_hash = $1', [tokenHash]).catch(() => {});
  void query('UPDATE users SET last_seen = now() WHERE id = $1', [r.rows[0].id]).catch(() => {});

  req.user = r.rows[0];
  req.sessionTokenHash = tokenHash;
  next();
}

const asyncRoute =
  (fn: (req: Request, res: Response) => Promise<any>) => (req: Request, res: Response, next: NextFunction) =>
    fn(req, res).catch(next);

const AVATARS = ['#9fd9d3', '#FFB5A7', '#FFD700', '#bfdde6', '#4FC3D9', '#4ADE80', '#FF8C69'];

// `mail` and `baseUrl` are here so a deploy can be checked without sending
// anything. Both are otherwise only discoverable by a user not receiving their
// signup email, or receiving one whose link goes nowhere.
//
// `baseUrl` is the host that verification links are built from. It is reported
// because setting it to a domain that does not serve the app yet is a silent,
// entirely plausible mistake — the app keeps working, signup keeps working, and
// only the emailed link is dead. Not a secret: it is a public URL, and the
// value is echoed rather than the environment variable's presence, because
// "set" and "set correctly" are different questions.
app.get('/api/health', (_req, res) =>
  res.json({
    ok: true,
    service: 'reefie-api',
    mail: mailConfigured,
    baseUrl: process.env.PUBLIC_BASE_URL ?? null,
    time: Date.now(),
  })
);

// ── names ───────────────────────────────────────────────────────────────────
const NAME_RE = /^[\p{L}\p{N} ._-]{2,20}$/u;

/** Returns an error string, or null if the name is well-formed. */
function validateName(name: string): string | null {
  if (name.length < 2) return 'Name must be at least 2 characters.';
  if (name.length > 20) return 'Name must be 20 characters or fewer.';
  if (!NAME_RE.test(name)) return 'Use letters, numbers, spaces, . _ or - only.';
  // Deliberately vague wording: naming the rule invites probing for gaps.
  if (isProfaneName(name)) return 'Pick a different name.';
  return null;
}

/** Is this name free? `selfId` lets an existing account keep its own name. */
async function nameTaken(name: string, selfId?: string) {
  const r = await query<{ id: string }>('SELECT id FROM users WHERE LOWER(name) = LOWER($1)', [name]);
  const owner = r.rows[0];
  return !!owner && owner.id !== selfId;
}

app.get(
  '/api/name-check',
  strictLimiter,
  asyncRoute(async (req, res) => {
    const name = String(req.query.name ?? '').trim();
    // Signed-in callers are renaming and may keep their current name; the
    // signup form has no session yet, so this is optional.
    const token = bearerToken(req.header('authorization'));
    let selfId: string | undefined;
    if (token) {
      const s = await query<{ user_id: string }>(
        'SELECT user_id FROM auth_sessions WHERE token_hash = $1 AND expires_at > now()',
        [hashToken(token)]
      );
      selfId = s.rows[0]?.user_id;
    }
    const problem = validateName(name);
    if (problem) return res.json({ available: false, reason: problem });
    if (await nameTaken(name, selfId)) return res.json({ available: false, reason: 'That name is taken.' });
    res.json({ available: true, reason: null });
  })
);

// ── accounts ────────────────────────────────────────────────────────────────

const avatarFor = (seed: string) =>
  AVATARS[Math.abs([...seed].reduce((a, c) => a + c.charCodeAt(0), 0)) % AVATARS.length];

/**
 * A real hash of a value nobody knows, verified against when the email does
 * not exist. Without it, "no such account" returns in microseconds while a
 * wrong password takes ~100 ms, and that difference enumerates the user table.
 */
const DUMMY_HASH = await hashPassword(randomUUID());

/**
 * Where the verification link points. An env override for production (so the
 * link survives the app moving behind a custom domain), falling back to the
 * host that served the request — which is what makes this work on a laptop and
 * on a preview deploy without configuration.
 */
function publicBase(req: Request): string {
  return (process.env.PUBLIC_BASE_URL ?? `${req.protocol}://${req.get('host')}`).replace(/\/$/, '');
}

/**
 * Issue a fresh verification link and mail it.
 *
 * Any outstanding links for the account are dropped first: two live links to
 * the same address is one more than is useful, and it means "Resend" reliably
 * invalidates whatever was in the last email rather than leaving a trail of
 * working credentials in an inbox.
 */
async function sendVerification(req: Request, user: { id: string; name: string; email: string }) {
  const v = newVerification();
  await tx(async (c) => {
    await c.query('DELETE FROM email_verifications WHERE user_id = $1', [user.id]);
    await c.query(
      'INSERT INTO email_verifications (token_hash, user_id, email, expires_at) VALUES ($1, $2, $3, $4)',
      [v.tokenHash, user.id, user.email, v.expiresAt]
    );
  });
  const link = `${publicBase(req)}/verify-email?token=${v.token}`;
  await sendMail({ to: user.email, ...verificationEmail(user.name, link) });
}

/** What the client gets back on any successful sign-in. */
async function sessionResponse(res: Response, user: User) {
  const s = newSession();
  await query('INSERT INTO auth_sessions (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
    s.tokenHash,
    user.id,
    s.expiresAt,
  ]);
  res.json({
    token: s.token,
    expiresAt: s.expiresAt.toISOString(),
    user,
    collection: await collectionOf(user.id),
  });
}

/** Create an account. Email + password + the diver name others will see. */
app.post(
  '/api/auth/signup',
  strictLimiter,
  asyncRoute(async (req, res) => {
    const email = normaliseEmail(String(req.body?.email ?? ''));
    const password = String(req.body?.password ?? '');
    const name = String(req.body?.name ?? '').trim();

    const emailProblem = validateEmail(email);
    if (emailProblem) return res.status(400).json({ error: emailProblem, field: 'email' });
    const passwordProblem = validatePassword(password);
    if (passwordProblem) return res.status(400).json({ error: passwordProblem, field: 'password' });
    const nameProblem = validateName(name);
    if (nameProblem) return res.status(400).json({ error: nameProblem, field: 'name' });

    if (await nameTaken(name)) return res.status(409).json({ error: 'That name is taken.', field: 'name' });

    const id = randomUUID();
    const passwordHash = await hashPassword(password);

    try {
      await tx(async (c) => {
        await c.query(
          `INSERT INTO users (id, name, initial, avatar_bg, email, password_hash)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [id, name, name[0].toUpperCase(), avatarFor(email), email, passwordHash]
        );
        await c.query('INSERT INTO user_stats (user_id) VALUES ($1)', [id]);
      });
    } catch (e: any) {
      // Two signups can race past the pre-checks; the unique indexes are the
      // real arbiters, so translate a violation into the same friendly error.
      if (e?.code === '23505') {
        const onEmail = String(e?.constraint ?? '').includes('email');
        return res.status(409).json({
          error: onEmail ? 'There is already an account with that email.' : 'That name is taken.',
          field: onEmail ? 'email' : 'name',
        });
      }
      throw e;
    }

    const u = await query<User>(`SELECT ${USER_COLS} FROM users WHERE id = $1`, [id]);

    // Deliberately not awaited into the response. Verification is a nudge, not
    // a gate — the account is usable this second — so a slow or failing mail
    // provider must not turn a successful signup into an error the user reads
    // as "it didn't work". They land in the app; the banner offers Resend.
    void sendVerification(req, { id, name, email }).catch((e) =>
      console.error('[reefie-api] verification send failed:', e.message)
    );

    await sessionResponse(res, u.rows[0]);
  })
);

/** Sign in to an existing account. */
app.post(
  '/api/auth/login',
  strictLimiter,
  asyncRoute(async (req, res) => {
    const email = normaliseEmail(String(req.body?.email ?? ''));
    const password = String(req.body?.password ?? '');

    const r = await query<User & { password_hash: string | null }>(
      `SELECT ${USER_COLS}, password_hash FROM users WHERE LOWER(email) = $1`,
      [email]
    );
    const row = r.rows[0];

    // One message for "no such email" and "wrong password", and the hash is
    // verified even when there is no user, so response time does not leak
    // which addresses have accounts.
    const ok = await verifyPassword(password, row?.password_hash ?? DUMMY_HASH);
    if (!row || !ok) return res.status(401).json({ error: 'That email and password don’t match.' });

    // Drop the hash before this object can reach a response body.
    const { password_hash: _omit, ...user } = row;

    void pruneExpiredSessions().catch(() => {});
    await sessionResponse(res, user);
  })
);

/** Sign out this device. Other devices keep their sessions. */
app.post(
  '/api/auth/logout',
  requireUser,
  asyncRoute(async (req, res) => {
    await query('DELETE FROM auth_sessions WHERE token_hash = $1', [req.sessionTokenHash]);
    res.json({ ok: true });
  })
);

/**
 * Which ways in actually work right now.
 *
 * This exists so the sign-in screen can render only buttons that do something.
 * A "Continue with Apple" button that shows the system sheet and then fails is
 * Guideline 2.1 — the same shape of problem as the purchase kill-switches that
 * had to come out — and the honest fix is for the server to say what it
 * supports rather than for the app to guess.
 *
 * Unauthenticated and cheap on purpose: it is fetched before anyone is signed
 * in, and the client defaults to hiding a method rather than showing one, so a
 * failed probe is safe.
 */
/**
 * Sign in with Apple. Off until the Apple Developer Program enrolment (B1)
 * exists: the capability is enabled on the App ID in the developer portal, and
 * verifying the identity token server-side needs a Services ID and a key that
 * only a paid account can create.
 *
 * Flipping this to true is not enough on its own — the route below has to be
 * implemented first. It is a named constant so the two can't drift apart
 * silently, and so `/api/auth/methods` never advertises something that 501s.
 */
const APPLE_SIGN_IN_READY = false;

app.get('/api/auth/methods', (_req, res) =>
  res.json({ email: true, apple: APPLE_SIGN_IN_READY })
);

app.post('/api/auth/apple', strictLimiter, (_req, res) =>
  res.status(501).json({ error: 'Sign in with Apple isn’t available yet.', unavailable: true })
);

// ── email verification ──────────────────────────────────────────────────────
// Soft by design: an unverified account is a whole account. This exists so a
// diver who loses their phone can prove the address is theirs, not to hold the
// app hostage while an email crosses the internet.

/** Send another verification link to the address already on the account. */
app.post(
  '/api/auth/verify/resend',
  strictLimiter,
  requireUser,
  asyncRoute(async (req, res) => {
    const user = req.user!;
    if (!user.email) return res.status(400).json({ error: 'This account has no email address.' });
    if (user.email_verified_at) return res.json({ sent: false, alreadyVerified: true });
    if (!canSendMail) {
      // Say so rather than reporting a send that will never happen. The app
      // shows this verbatim, so it has to be true.
      return res.status(503).json({ error: 'We can’t send email right now. Try again later.' });
    }
    // Here the send *is* the action, so unlike signup a failure is the answer —
    // but it has to be *our* answer. Letting this throw to the global handler
    // returned the provider's raw body verbatim, so a misconfigured sending
    // domain surfaced in the app as an alert containing Resend's JSON. Keep the
    // detail in the logs, where it is useful, and give the user a sentence.
    try {
      await sendVerification(req, { id: user.id, name: user.name, email: user.email });
    } catch (e) {
      console.error('[reefie-api] verification resend failed:', (e as Error).message);
      return res.status(502).json({ error: 'We couldn’t send that email just now. Try again in a moment.' });
    }
    res.json({ sent: true, alreadyVerified: false });
  })
);

/**
 * Redeem a link. This is opened in a mail client's browser, not in the app, so
 * it answers with a page rather than JSON and never requires a session — the
 * token in the URL is the whole credential.
 *
 * The app learns the result on its next sync rather than through a deep link:
 * one code path, and it works whether the link was opened on this phone, a
 * laptop, or a tablet.
 */
app.get(
  '/verify-email',
  asyncRoute(async (req, res) => {
    const token = String(req.query.token ?? '');
    const r = token
      ? await query<{ user_id: string; email: string }>(
          `DELETE FROM email_verifications
            WHERE token_hash = $1 AND expires_at > now()
        RETURNING user_id, email`,
          [hashToken(token)]
        )
      : { rows: [] as { user_id: string; email: string }[] };

    const row = r.rows[0];
    if (!row) {
      return res
        .status(400)
        .type('html')
        .send(
          verifyPage(
            'This link has expired',
            `Verification links last ${VERIFY_HOURS} hours. Open Reefie and tap “Resend” to get a fresh one.`
          )
        );
    }

    // Only mark verified if the address still matches the one the link was
    // mailed to. Changing your email must not be confirmable by a link sent to
    // the previous address.
    const u = await query<{ name: string }>(
      `UPDATE users SET email_verified_at = now()
        WHERE id = $1 AND LOWER(email) = LOWER($2)
    RETURNING name`,
      [row.user_id, row.email]
    );
    if (!u.rows[0]) {
      return res
        .status(400)
        .type('html')
        .send(verifyPage('That address has changed', 'Open Reefie and tap “Resend” to confirm your current email.'));
    }

    res.type('html').send(verifyPage('Email confirmed', 'You can close this and go back to Reefie. Happy diving.'));
  })
);

/** A whole page in one function. It is two lines of text; a template file would be more moving parts than markup. */
function verifyPage(title: string, body: string): string {
  const esc = (s: string) => s.replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]!);
  return `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Reefie</title>
<style>
  body { margin:0; min-height:100vh; display:grid; place-items:center; padding:24px;
         background:#0A2540; color:#F0F7FA;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif; }
  main { max-width:26rem; text-align:center; }
  h1 { font-size:1.6rem; margin:0 0 .6rem; }
  p { color:#9DB4C0; line-height:1.5; margin:0; }
</style>
</head><body><main><h1>${esc(title)}</h1><p>${esc(body)}</p></main></body></html>`;
}

app.get(
  '/api/me',
  requireUser,
  asyncRoute(async (req, res) => {
    const stats = await query('SELECT * FROM user_stats WHERE user_id = $1', [req.user!.id]);
    res.json({ user: req.user, collection: await collectionOf(req.user!.id), stats: stats.rows[0] ?? null });
  })
);

/**
 * Change the diver name others see.
 *
 * This route is new, and it is new because it had to be. The name used to be
 * persisted as a side effect of `POST /api/register`, which the client called
 * on every sync — so "renaming" was really "re-registering". Accounts removed
 * that call, and without this the Edit button on the profile screen would have
 * gone on working locally while the leaderboard kept showing the old name.
 */
app.patch(
  '/api/me/name',
  strictLimiter,
  requireUser,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name ?? '').trim();
    const problem = validateName(name);
    if (problem) return res.status(400).json({ error: problem, field: 'name' });
    if (await nameTaken(name, req.user!.id)) {
      return res.status(409).json({ error: 'That name is taken.', field: 'name' });
    }
    try {
      await query('UPDATE users SET name = $1, initial = $2 WHERE id = $3', [
        name,
        name[0].toUpperCase(),
        req.user!.id,
      ]);
    } catch (e: any) {
      // The unique index is the real arbiter when two renames race.
      if (e?.code === '23505') return res.status(409).json({ error: 'That name is taken.', field: 'name' });
      throw e;
    }
    const u = await query<User>(`SELECT ${USER_COLS} FROM users WHERE id = $1`, [req.user!.id]);
    res.json({ user: u.rows[0] });
  })
);

/**
 * Delete the calling account and everything that hangs off it. Every child
 * table (user_species, user_stats, friendships both directions, room_members,
 * room_dives, trades on either side, reports on either side, rooms.host_id)
 * references users(id) ON DELETE CASCADE — verified against production — so a
 * single DELETE on users is the whole job and can't leave orphans behind.
 * Note: a room this user *hosts* cascades away even with other members still
 * inside. Accepted for beta — rooms are cheap to recreate, and a host-less
 * room would break every query that joins rooms to its host.
 */
app.delete(
  '/api/me',
  requireUser,
  asyncRoute(async (req, res) => {
    await query('DELETE FROM users WHERE id = $1', [req.user!.id]);
    res.json({ deleted: true });
  })
);

/**
 * Flag another diver for a human to look at. Deliberately minimal: no dedupe,
 * no self-report guard — moderation reads the raw table and noise there is
 * cheaper than a client contract with edge cases.
 */
app.post(
  '/api/report',
  requireUser,
  asyncRoute(async (req, res) => {
    const targetId = String(req.body?.targetId ?? '').trim();
    // Reason is free text from a stranger — cap it so the table can't be used
    // as a dumping ground.
    const reason = req.body?.reason == null ? null : String(req.body.reason).slice(0, 500);
    if (!targetId) return res.status(400).json({ error: 'targetId required' });

    const target = await query('SELECT 1 FROM users WHERE id = $1', [targetId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'no such user' });

    await query('INSERT INTO reports (id, reporter_id, target_id, reason) VALUES ($1,$2,$3,$4)', [
      'rp' + randomUUID().slice(0, 8),
      req.user!.id,
      targetId,
      reason,
    ]);
    res.status(201).json({ ok: true });
  })
);

// ── blocking ────────────────────────────────────────────────────────────────
/**
 * A SQL predicate that hides any diver on either side of a block, for use in a
 * query that already has the other diver's id in scope. `me` and `them` are the
 * SQL expressions naming the two ids — usually a placeholder and a column.
 *
 * Symmetric on purpose: blocking is not just "hide them from me". If it only
 * cut one direction, the blocked diver could still see, trade with and follow
 * the person who blocked them, which is not what Guideline 1.2 asks for.
 */
const notBlocked = (me: string, them: string) => `
  NOT EXISTS (
    SELECT 1 FROM blocks b
     WHERE (b.blocker_id = ${me} AND b.blocked_id = ${them})
        OR (b.blocker_id = ${them} AND b.blocked_id = ${me})
  )`;

/**
 * Block a diver. Also tears down the friendship in both directions — staying
 * "friends" with someone you have blocked is a contradiction the rest of the
 * app would have to keep special-casing. Idempotent, so the button can't fail
 * by being pressed twice.
 */
app.post(
  '/api/blocks',
  strictLimiter,
  requireUser,
  asyncRoute(async (req, res) => {
    const targetId = String(req.body?.targetId ?? '').trim();
    const me = req.user!.id;
    if (!targetId) return res.status(400).json({ error: 'targetId required' });
    if (targetId === me) return res.status(400).json({ error: 'You cannot block yourself.' });

    const target = await query('SELECT 1 FROM users WHERE id = $1', [targetId]);
    if (!target.rows[0]) return res.status(404).json({ error: 'no such user' });

    await tx(async (c) => {
      await c.query(
        `INSERT INTO blocks (blocker_id, blocked_id) VALUES ($1,$2)
         ON CONFLICT (blocker_id, blocked_id) DO NOTHING`,
        [me, targetId]
      );
      await c.query(
        `DELETE FROM friendships
          WHERE (user_id = $1 AND friend_id = $2) OR (user_id = $2 AND friend_id = $1)`,
        [me, targetId]
      );
      // Cancel anything in flight between the two, so a blocked diver's pending
      // offer can't sit in the other person's inbox after the block.
      await c.query(
        `UPDATE trades SET status = 'cancelled', resolved_at = now()
          WHERE status = 'pending'
            AND ((from_id = $1 AND to_id = $2) OR (from_id = $2 AND to_id = $1))`,
        [me, targetId]
      );
    });
    res.status(201).json({ ok: true });
  })
);

/** Unblock. Does not restore the friendship — that has to be deliberate. */
app.delete(
  '/api/blocks/:id',
  requireUser,
  asyncRoute(async (req, res) => {
    await query('DELETE FROM blocks WHERE blocker_id = $1 AND blocked_id = $2', [
      req.user!.id,
      String(req.params.id),
    ]);
    res.json({ ok: true });
  })
);

/** Who this diver has blocked, so the app can offer an unblock list. */
app.get(
  '/api/blocks',
  requireUser,
  asyncRoute(async (req, res) => {
    const r = await query(
      `SELECT u.id, u.name, u.initial, u.avatar_bg
         FROM blocks b JOIN users u ON u.id = b.blocked_id
        WHERE b.blocker_id = $1
        ORDER BY b.created_at DESC`,
      [req.user!.id]
    );
    res.json(
      r.rows.map((x: any) => ({ id: x.id, name: x.name, initial: x.initial, avatarBg: x.avatar_bg }))
    );
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
                -- Weekly total: keep accruing within the current week, otherwise
                -- start this week fresh from these minutes. date_trunc('week') is
                -- the Monday 00:00 of the week, so everyone rolls over together.
                week_mins = CASE WHEN week_start = date_trunc('week', now())::date
                                 THEN week_mins + $2 ELSE $2 END,
                week_start = date_trunc('week', now())::date,
                updated_at = now()
          WHERE user_id = $1`,
        [me, mins, speciesId ? 1 : 0]
      );
    });

    const stats = await query('SELECT * FROM user_stats WHERE user_id = $1', [me]);
    res.json({ collection: await collectionOf(me), stats: stats.rows[0] });
  })
);

// Profile photos are deliberately not a v1 feature. An uploaded photo shown to
// strangers on the leaderboard is user-generated content, and App Review
// Guideline 1.2 requires a moderation path for that — object storage, a review
// queue, and a User Content → Photos entry on the privacy label. The generated
// initials tile carries no such burden, so the upload route is gone and
// avatar_url is never read back out. The column is left in place so any rows
// written during the beta stay recoverable if photos return with moderation.

/**
 * Add a friend by diver name. Names are unique, so the name is the handle.
 * Symmetric: both of you see each other immediately, with no accept step —
 * a pending-request flow is more than a private beta needs.
 */
app.post(
  '/api/friends',
  strictLimiter,
  requireUser,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name ?? '').trim();
    if (!name) return res.status(400).json({ error: 'Enter a diver name.' });

    const found = await query<{ id: string; name: string }>(
      'SELECT id, name FROM users WHERE LOWER(name) = LOWER($1)',
      [name]
    );
    const other = found.rows[0];
    if (!other) return res.status(404).json({ error: `No diver called “${name}”.` });
    if (other.id === req.user!.id) return res.status(400).json({ error: 'That’s you.' });

    // Either direction of a block stops the add. The message is the same as the
    // not-found one on purpose: telling someone "they blocked you" hands a
    // harasser a confirmation, and telling them nothing costs an honest user
    // nothing, since they can only reach this by typing an exact diver name.
    const blocked = await query(
      `SELECT 1 WHERE NOT ${notBlocked('$1', '$2')}`,
      [req.user!.id, other.id]
    );
    if (blocked.rows[0]) return res.status(404).json({ error: `No diver called “${name}”.` });

    await tx(async (c) => {
      await c.query(
        `INSERT INTO friendships (user_id, friend_id) VALUES ($1,$2), ($2,$1)
         ON CONFLICT DO NOTHING`,
        [req.user!.id, other.id]
      );
    });
    res.status(201).json({ id: other.id, name: other.name });
  })
);

/** Your friends on this server. */
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
          AND EXISTS (SELECT 1 FROM friendships f WHERE f.user_id = $1 AND f.friend_id = u.id)
          AND ${notBlocked('$1', 'u.id')}
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
    // The board is this week's focus, and it resets every Monday for everyone.
    // A diver whose week_start isn't the current week counts as zero this week —
    // so the reset is implicit and needs no scheduled job to wipe the table.
    const r = await query(
      `SELECT u.id, u.name, u.initial, u.avatar_bg,
              CASE WHEN s.week_start = date_trunc('week', now())::date
                   THEN COALESCE(s.week_mins, 0) ELSE 0 END AS week_mins
         FROM users u LEFT JOIN user_stats s ON s.user_id = u.id
        WHERE ${notBlocked('$1', 'u.id')}
        ORDER BY week_mins DESC, u.last_seen DESC LIMIT 25`,
      [req.user!.id]
    );
    const medal = ['#FFD700', '#8fa8b5', '#c98b4a'];
    res.json(
      r.rows.map((x: any, i: number) => ({
        rank: String(i + 1),
        name: x.id === req.user!.id ? `${x.name} (you)` : x.name,
        initial: x.initial,
        avatarBg: x.avatar_bg,
        time: `${Math.floor(Number(x.week_mins) / 60)}h ${Number(x.week_mins) % 60}m`,
        rankFg: medal[i] ?? '#8fa8b5',
        you: x.id === req.user!.id,
      }))
    );
  })
);

// ── rooms ───────────────────────────────────────────────────────────────────
/**
 * Collective progression, derived from the room's finished dives rather than a
 * counter anyone could inflate:
 *   sharedDepth — every metre the room has ever dived, added up. The number that
 *                 makes a room feel like it's going somewhere together.
 *   corals      — one coral planted per full hour the room has focused.
 */
const CORAL_PER_MINS = 60;

async function roomsWithMembers() {
  const r = await query(
    `SELECT r.id, r.name, r.kind, r.depth, r.schedule, r.start_min, r.start_at,
            h.name AS host, r.host_id,
            COALESCE(JSON_AGG(DISTINCT JSONB_BUILD_OBJECT('id', u.id, 'initial', u.initial, 'bg', u.avatar_bg))
                     FILTER (WHERE u.id IS NOT NULL), '[]') AS participants,
            COALESCE(d.total_mins, 0) AS total_mins,
            COALESCE(d.total_depth, 0) AS total_depth,
            COALESCE(d.dives, 0) AS dives
       FROM rooms r
       JOIN users h ON h.id = r.host_id
       LEFT JOIN room_members m ON m.room_id = r.id
       LEFT JOIN users u ON u.id = m.user_id
       LEFT JOIN (
         SELECT room_id,
                SUM(mins)::int  AS total_mins,
                SUM(depth)::int AS total_depth,
                COUNT(*)::int   AS dives
           FROM room_dives GROUP BY room_id
       ) d ON d.room_id = r.id
      GROUP BY r.id, h.name, d.total_mins, d.total_depth, d.dives
      ORDER BY r.created_at DESC`
  );
  return r.rows.map((x: any) => ({
    id: x.id,
    name: x.name,
    kind: x.kind,
    depth: x.depth === null ? null : Number(x.depth),
    schedule: x.schedule,
    startMin: x.start_min === null ? null : Number(x.start_min),
    startAt: x.start_at,
    host: x.host,
    hostId: x.host_id,
    participants: x.participants,
    progress: {
      dives: Number(x.dives),
      totalMins: Number(x.total_mins),
      sharedDepth: Number(x.total_depth),
      corals: Math.floor(Number(x.total_mins) / CORAL_PER_MINS),
    },
  }));
}

app.get('/api/rooms', requireUser, asyncRoute(async (_req, res) => res.json(await roomsWithMembers())));

app.post(
  '/api/rooms',
  requireUser,
  asyncRoute(async (req, res) => {
    const name = String(req.body?.name ?? '').trim();
    const kind = String(req.body?.kind ?? 'room');
    const schedule = String(req.body?.schedule ?? 'daily');

    if (!name) return res.status(400).json({ error: 'Give the room a name.' });
    // A room name shows on every member's screen, so it goes through the same
    // moderation gate as diver names.
    if (isProfaneName(name)) return res.status(400).json({ error: 'Pick a different name.' });
    if (kind !== 'room' && kind !== 'expedition') return res.status(400).json({ error: 'Unknown room kind.' });
    if (schedule !== 'daily' && schedule !== 'once') return res.status(400).json({ error: 'Unknown schedule.' });

    // Expeditions commit everyone to one length; rooms leave it to each diver.
    let depth: number | null = null;
    if (kind === 'expedition') {
      const d = Number(req.body?.depth);
      if (!Number.isFinite(d) || d < 10 || d > 120) {
        return res.status(400).json({ error: 'An expedition needs a depth between 10 and 120 m.' });
      }
      depth = Math.round(d);
    }

    let startMin: number | null = null;
    let startAt: string | null = null;
    if (schedule === 'daily') {
      const m = Number(req.body?.startMin);
      if (!Number.isFinite(m) || m < 0 || m > 1439) {
        return res.status(400).json({ error: 'Pick a start time.' });
      }
      startMin = Math.round(m);
    } else {
      const at = new Date(String(req.body?.startAt ?? ''));
      if (Number.isNaN(at.getTime())) return res.status(400).json({ error: 'Pick a start date and time.' });
      if (at.getTime() < Date.now() - 60_000) return res.status(400).json({ error: 'That start time is in the past.' });
      startAt = at.toISOString();
    }

    const id = 'r' + randomUUID().slice(0, 8);
    await tx(async (c) => {
      await c.query(
        `INSERT INTO rooms (id, name, kind, depth, schedule, start_min, start_at, host_id)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
        [id, name, kind, depth, schedule, startMin, startAt, req.user!.id]
      );
      await c.query('INSERT INTO room_members (room_id, user_id) VALUES ($1,$2)', [id, req.user!.id]);
    });
    res.status(201).json((await roomsWithMembers()).find((r: any) => r.id === id));
  })
);

/**
 * Report a finished dive against a room, feeding collective progression.
 * Membership is checked server-side so you can't bank depth into a room you
 * aren't in.
 */
app.post(
  '/api/rooms/:id/dive',
  requireUser,
  asyncRoute(async (req, res) => {
    const mins = Number(req.body?.mins);
    const depth = Number(req.body?.depth);
    if (!Number.isFinite(mins) || mins <= 0) return res.status(400).json({ error: 'mins required' });
    if (!Number.isFinite(depth) || depth < 10 || depth > 120) return res.status(400).json({ error: 'depth must be 10-120' });

    const member = await query('SELECT 1 FROM room_members WHERE room_id = $1 AND user_id = $2', [
      req.params.id,
      req.user!.id,
    ]);
    if (!member.rows[0]) return res.status(403).json({ error: 'You are not in that room.' });

    await query(
      'INSERT INTO room_dives (id, room_id, user_id, mins, depth) VALUES ($1,$2,$3,$4,$5)',
      ['d' + randomUUID().slice(0, 8), req.params.id, req.user!.id, Math.round(mins), Math.round(depth)]
    );
    res.status(201).json((await roomsWithMembers()).find((r: any) => r.id === req.params.id));
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
    // A room with nobody in it is litter — the last diver out deletes it.
    // Done in one transaction so two people leaving at once can't both read a
    // non-empty room and leave it stranded.
    const removed = await tx(async (c) => {
      // Lock the room row, not the member count: Postgres rejects FOR UPDATE
      // alongside an aggregate. Locking the room still serialises two people
      // leaving at once, which is the race we care about.
      await c.query('SELECT 1 FROM rooms WHERE id = $1 FOR UPDATE', [req.params.id]);
      await c.query('DELETE FROM room_members WHERE room_id = $1 AND user_id = $2', [req.params.id, req.user!.id]);
      const left = await c.query<{ n: string }>(
        'SELECT count(*)::int AS n FROM room_members WHERE room_id = $1',
        [req.params.id]
      );
      if (Number(left.rows[0]?.n ?? 0) === 0) {
        await c.query('DELETE FROM rooms WHERE id = $1', [req.params.id]);
        return true;
      }
      return false;
    });
    if (removed) return res.json({ id: req.params.id, removed: true });
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

    // A block cuts contact, and an unsolicited trade offer is contact.
    const blocked = await query(`SELECT 1 WHERE NOT ${notBlocked('$1', '$2')}`, [me, toId]);
    if (blocked.rows[0]) return res.status(403).json({ error: 'You can’t trade with that diver.' });

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

// ── legal pages ─────────────────────────────────────────────────────────────
// Resolved relative to this file, not the working directory, so the same path
// works from src/ under tsx and from dist/ under node — both sit one level
// below the server root, next to public/.
const PUBLIC_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'public');

const legalPage = (file: string) => (_req: Request, res: Response) => {
  res.sendFile(path.join(PUBLIC_DIR, file), (err) => {
    // The HTML ships separately from the code; until it lands, answer plainly
    // rather than surfacing a filesystem error to app-store reviewers.
    if (err && !res.headersSent) res.status(404).type('text/plain').send('coming soon');
  });
};

// Public on purpose: app-store review and signed-out users must be able to
// read these, so no requireUser and no strict limiter.
app.get('/privacy', legalPage('privacy.html'));
app.get('/terms', legalPage('terms.html'));
// App Store Connect requires a Support URL, and Guideline 1.2 requires a
// published way to contact someone about another user's behaviour. This is both.
app.get('/support', legalPage('support.html'));

// ── errors ──────────────────────────────────────────────────────────────────
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  const status = err?.status ?? 500;
  if (status >= 500) console.error('[reefie-api]', err);
  res.status(status).json({ error: err?.message ?? 'server error' });
});

initSchema()
  .then(() => {
    app.listen(PORT, () => console.log(`Reefie API listening on http://0.0.0.0:${PORT}`));
  })
  .catch((e) => {
    console.error('[reefie-api] failed to init schema:', e.message);
    process.exit(1);
  });

process.on('SIGTERM', () => pool.end().then(() => process.exit(0)));
