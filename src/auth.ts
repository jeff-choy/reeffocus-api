import {
  createHash,
  randomBytes,
  scrypt as scryptCb,
  timingSafeEqual,
} from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(scryptCb) as (
  password: string | Buffer,
  salt: string | Buffer,
  keylen: number
) => Promise<Buffer>;

// ── passwords ───────────────────────────────────────────────────────────────
// scrypt from node:crypto rather than bcrypt or argon2: both of those are
// native modules that have to compile on the host, and this needs no build
// step, no new dependency and no supply-chain surface for a server whose whole
// dependency list currently fits on one screen. The cost parameters below are
// node's defaults, which land around 100 ms per hash — slow enough to make
// offline guessing expensive, fast enough that a login is not a spinner.
const KEY_LEN = 64;
const SALT_LEN = 16;

/** Below this, a password is guessable; above it, length is what matters. */
export const MIN_PASSWORD = 8;
/**
 * scrypt hashes the whole input, so an unbounded password is a free way to
 * make the server do unbounded work. 128 is far past any real passphrase.
 */
export const MAX_PASSWORD = 128;

/** `scrypt$<salt hex>$<key hex>`, so the format can change without a migration. */
export async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(SALT_LEN);
  const key = await scrypt(password, salt, KEY_LEN);
  return `scrypt$${salt.toString('hex')}$${key.toString('hex')}`;
}

/** Constant-time. Returns false rather than throwing on a malformed stored hash. */
export async function verifyPassword(password: string, stored: string | null): Promise<boolean> {
  if (!stored) return false;
  const [scheme, saltHex, keyHex] = stored.split('$');
  if (scheme !== 'scrypt' || !saltHex || !keyHex) return false;
  let expected: Buffer;
  try {
    expected = Buffer.from(keyHex, 'hex');
  } catch {
    return false;
  }
  if (expected.length !== KEY_LEN) return false;
  const actual = await scrypt(password, Buffer.from(saltHex, 'hex'), KEY_LEN);
  return timingSafeEqual(actual, expected);
}

/** Returns an error string, or null if the password is acceptable. */
export function validatePassword(password: string): string | null {
  if (password.length < MIN_PASSWORD) return `Password must be at least ${MIN_PASSWORD} characters.`;
  if (password.length > MAX_PASSWORD) return `Password must be ${MAX_PASSWORD} characters or fewer.`;
  // No composition rules on purpose. Requiring a symbol and a digit pushes
  // people towards Password1! and away from a long passphrase, which is worse.
  return null;
}

// ── session tokens ──────────────────────────────────────────────────────────
// Opaque random tokens in a table, not JWTs. A JWT cannot be revoked without a
// denylist, which is a table — so this is the same storage with none of the
// signing-key handling, and "sign out everywhere" and "delete account kills
// every session" both fall out of the foreign key for free.

/** A year. This is a phone app; being logged out on a commute is a bug. */
export const SESSION_DAYS = 365;

export type NewSession = { token: string; tokenHash: string; expiresAt: Date };

export function newSession(): NewSession {
  // 256 bits, url-safe so it survives a header and a keychain round trip.
  const token = randomBytes(32).toString('base64url');
  return {
    token,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + SESSION_DAYS * 86_400_000),
  };
}

/**
 * Only the hash is stored, so a database leak does not hand out live sessions.
 * SHA-256 with no salt is right here and wrong for passwords: the input is 256
 * bits of entropy we generated, so there is nothing to guess and nothing a
 * rainbow table can precompute.
 */
export function hashToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

/** Pulls the token out of `Authorization: Bearer <token>`, or null. */
export function bearerToken(header: string | undefined): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(\S+)$/i.exec(header.trim());
  return m ? m[1] : null;
}

// ── email verification ──────────────────────────────────────────────────────

/**
 * Long enough that an email sitting overnight still works, short enough that a
 * link forwarded or left in an old inbox stops being a way in. A user who
 * misses the window taps Resend; nothing is lost.
 */
export const VERIFY_HOURS = 24;

/**
 * Same shape and same storage discipline as a session token — 256 random bits,
 * only the hash persisted. A verification link is a bearer credential that
 * travels through email and sits in an inbox, so it deserves no less care than
 * the session it can vouch for.
 */
export function newVerification(): NewSession {
  const token = randomBytes(32).toString('base64url');
  return {
    token,
    tokenHash: hashToken(token),
    expiresAt: new Date(Date.now() + VERIFY_HOURS * 3_600_000),
  };
}

// ── email ───────────────────────────────────────────────────────────────────

/**
 * Deliberately permissive. The only address that matters is one the user can
 * receive at, and no regex can decide that — a rule strict enough to reject
 * typos also rejects real addresses. This catches shape errors; delivery is
 * what actually proves an address.
 */
const EMAIL_RE = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

export const MAX_EMAIL = 254; // RFC 5321's limit on a forward path.

/** Lowercased and trimmed, so `A@b.com` and `a@b.com` are one account. */
export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Returns an error string, or null if the address is well-formed. */
export function validateEmail(email: string): string | null {
  if (!email) return 'Enter your email address.';
  if (email.length > MAX_EMAIL) return 'That email address is too long.';
  if (!EMAIL_RE.test(email)) return 'That doesn’t look like an email address.';
  return null;
}
