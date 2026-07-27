import { createPublicKey, createVerify } from 'node:crypto';

/**
 * Verifying a Sign in with Apple identity token.
 *
 * For a **native iOS** sign-in this needs no secrets at all — no Services ID,
 * no private key, no client secret. Apple signs the identity token with a key
 * whose public half is published at the JWKS endpoint below, so anyone can
 * check the signature. The client secret and Services ID belong to the *web*
 * sign-in flow and the token-revocation endpoint, neither of which Reefie uses.
 *
 * (This file exists because that distinction was got wrong earlier: the Apple
 * route was left returning 501 on the belief that it was blocked behind the
 * developer-program enrolment. Only the App ID *capability* ever was.)
 *
 * Implemented against node:crypto rather than a JWT library. Node imports a JWK
 * directly, so verification is a signature check and some claim comparisons —
 * and the alternative was a dependency that would have to be trusted with the
 * one thing standing between a stranger and an account.
 */

const APPLE_ISSUER = 'https://appleid.apple.com';
const APPLE_JWKS_URL = 'https://appleid.apple.com/auth/keys';

/** Claims Reefie actually uses. Apple sends more; these are the load-bearing ones. */
export type AppleIdentity = {
  /** Apple's stable, app-specific user id. This is the account key. */
  sub: string;
  email: string | null;
  /**
   * Whether Apple vouches for the address. Private-relay addresses are verified
   * by definition. Only ever true or false — Apple sends it as either a boolean
   * or the *strings* "true"/"false" depending on the flow, which is exactly the
   * sort of thing that silently becomes truthy if you don't normalise it.
   */
  emailVerified: boolean;
};

type Jwk = { kid: string; kty: string; alg: string; n: string; e: string; use?: string };

// Apple rotates these keys, so they cannot be pinned — but they also change
// rarely, and re-fetching on every sign-in would put Apple's availability in
// the critical path of every login. Cached, with a refetch when an unknown kid
// shows up, which is precisely the moment a rotation has happened.
let cachedKeys: Map<string, Jwk> | null = null;
let cachedAt = 0;
const CACHE_MS = 60 * 60 * 1000;

async function fetchKeys(): Promise<Map<string, Jwk>> {
  const res = await fetch(APPLE_JWKS_URL);
  if (!res.ok) throw new Error(`Could not fetch Apple's signing keys (${res.status}).`);
  const body = (await res.json()) as { keys: Jwk[] };
  const map = new Map(body.keys.map((k) => [k.kid, k]));
  cachedKeys = map;
  cachedAt = Date.now();
  return map;
}

async function keyFor(kid: string): Promise<Jwk> {
  if (!cachedKeys || Date.now() - cachedAt > CACHE_MS) await fetchKeys();
  let key = cachedKeys!.get(kid);
  if (!key) {
    // Unknown kid against a warm cache means Apple rotated. Refetch once.
    await fetchKeys();
    key = cachedKeys!.get(kid);
  }
  if (!key) throw new Error('Apple signed this token with an unrecognised key.');
  return key;
}

const b64urlToBuffer = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
const decodeSegment = (s: string) => JSON.parse(b64urlToBuffer(s).toString('utf8'));

/**
 * Verify an identity token and return the identity it asserts, or throw.
 *
 * Every check here is load-bearing:
 *  - the signature, or the token is forgeable;
 *  - `iss`, or a token from somewhere else could be replayed here;
 *  - `aud`, or a token minted for a *different app* would sign a user into
 *    Reefie — this is the check that makes the bundle id matter;
 *  - `exp`, or an old token works forever.
 */
export async function verifyAppleIdentityToken(token: string, bundleId: string): Promise<AppleIdentity> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Malformed Apple token.');
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { kid?: string; alg?: string };
  let payload: Record<string, unknown>;
  try {
    header = decodeSegment(headerB64);
    payload = decodeSegment(payloadB64);
  } catch {
    throw new Error('Malformed Apple token.');
  }

  // Apple uses RS256. Pinning it is what stops an "alg": "none" token, and a
  // token that claims HS256 from being verified with the public key as an HMAC
  // secret — both classic JWT forgeries.
  if (header.alg !== 'RS256') throw new Error('Unexpected Apple token algorithm.');
  if (!header.kid) throw new Error('Apple token has no key id.');

  const jwk = await keyFor(header.kid);
  const publicKey = createPublicKey({ key: jwk as any, format: 'jwk' });

  const verifier = createVerify('RSA-SHA256');
  verifier.update(`${headerB64}.${payloadB64}`);
  verifier.end();
  if (!verifier.verify(publicKey, b64urlToBuffer(signatureB64))) {
    throw new Error('Apple token signature is invalid.');
  }

  if (payload.iss !== APPLE_ISSUER) throw new Error('Apple token has the wrong issuer.');

  // aud is a string for a single audience; tolerate the array form too.
  const aud = payload.aud;
  const audOk = Array.isArray(aud) ? aud.includes(bundleId) : aud === bundleId;
  if (!audOk) throw new Error('Apple token was issued for a different app.');

  const exp = Number(payload.exp);
  if (!Number.isFinite(exp) || exp * 1000 <= Date.now()) throw new Error('Apple token has expired.');

  const sub = typeof payload.sub === 'string' ? payload.sub : '';
  if (!sub) throw new Error('Apple token carries no user id.');

  const email = typeof payload.email === 'string' ? payload.email : null;
  // Normalise the boolean-or-string, so "false" cannot read as true.
  const rawVerified = payload.email_verified;
  const emailVerified = rawVerified === true || rawVerified === 'true';

  return { sub, email, emailVerified };
}

/** Exposed for tests, so a case can start from a clean cache. */
export function __resetAppleKeyCache() {
  cachedKeys = null;
  cachedAt = 0;
}
