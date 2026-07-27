import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAX_EMAIL,
  MAX_PASSWORD,
  MIN_PASSWORD,
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
} from '../auth.js';

// These are the only things standing between a stranger and someone's account,
// so they are worth pinning down. The failure modes here are silent: a hash
// that verifies anything, a token that is guessable, an email normaliser that
// lets one person hold two accounts.

test('a password verifies against its own hash and nothing else', async () => {
  const hash = await hashPassword('correct horse battery staple');
  assert.equal(await verifyPassword('correct horse battery staple', hash), true);
  assert.equal(await verifyPassword('correct horse battery stapl', hash), false);
  assert.equal(await verifyPassword('', hash), false);
});

test('the same password hashes differently every time', async () => {
  // Per-hash salt. Without it, two people with the same password are visibly
  // the same row, and one cracked hash cracks every account that shares it.
  const a = await hashPassword('hunter2hunter2');
  const b = await hashPassword('hunter2hunter2');
  assert.notEqual(a, b);
  assert.equal(await verifyPassword('hunter2hunter2', a), true);
  assert.equal(await verifyPassword('hunter2hunter2', b), true);
});

test('verification refuses a malformed or missing stored hash', async () => {
  // A null here means an Apple-only account with no password. It must fail
  // closed, not throw and not pass.
  for (const stored of [null, '', 'not-a-hash', 'scrypt$', 'scrypt$abcd', 'bcrypt$aa$bb']) {
    assert.equal(await verifyPassword('anything', stored), false, `stored=${JSON.stringify(stored)}`);
  }
});

test('a truncated hash of the right scheme is still rejected', async () => {
  const hash = await hashPassword('a long enough password');
  const [scheme, salt, key] = hash.split('$');
  assert.equal(await verifyPassword('a long enough password', `${scheme}$${salt}$${key.slice(0, 32)}`), false);
});

test('password length is bounded at both ends', () => {
  assert.notEqual(validatePassword('a'.repeat(MIN_PASSWORD - 1)), null);
  assert.equal(validatePassword('a'.repeat(MIN_PASSWORD)), null);
  assert.equal(validatePassword('a'.repeat(MAX_PASSWORD)), null);
  // Unbounded input to a deliberately slow hash is a free denial of service.
  assert.notEqual(validatePassword('a'.repeat(MAX_PASSWORD + 1)), null);
});

test('password rules do not demand symbols or digits', () => {
  // A long passphrase must be acceptable, or people write Password1!.
  assert.equal(validatePassword('a quiet reef at dawn'), null);
});

test('session tokens are unique, url-safe and stored only as a hash', () => {
  const seen = new Set<string>();
  for (let i = 0; i < 500; i++) {
    const s = newSession();
    assert.match(s.token, /^[A-Za-z0-9_-]+$/, 'must survive a header and a keychain');
    assert.ok(s.token.length >= 40, 'must carry real entropy');
    assert.equal(seen.has(s.token), false, 'collision');
    seen.add(s.token);
    assert.equal(s.tokenHash, hashToken(s.token));
    assert.notEqual(s.tokenHash, s.token, 'the raw token must never be what is stored');
    assert.ok(s.expiresAt.getTime() > Date.now());
  }
});

test('token hashing is deterministic', () => {
  assert.equal(hashToken('abc'), hashToken('abc'));
  assert.notEqual(hashToken('abc'), hashToken('abd'));
});

test('bearerToken reads only a well-formed Authorization header', () => {
  assert.equal(bearerToken('Bearer abc123'), 'abc123');
  assert.equal(bearerToken('bearer abc123'), 'abc123'); // scheme is case-insensitive
  assert.equal(bearerToken('  Bearer   abc123  '), 'abc123');
  assert.equal(bearerToken(undefined), null);
  assert.equal(bearerToken(''), null);
  assert.equal(bearerToken('abc123'), null);
  assert.equal(bearerToken('Basic abc123'), null);
  assert.equal(bearerToken('Bearer a b'), null, 'a token has no spaces in it');
});

test('emails normalise to one account per address', () => {
  assert.equal(normaliseEmail('  Diver@Example.COM '), 'diver@example.com');
  assert.equal(normaliseEmail('a@b.co'), 'a@b.co');
});

test('email validation accepts real addresses', () => {
  for (const ok of [
    'a@b.co',
    'diver@example.com',
    'first.last+tag@sub.domain.co.uk',
    "o'brien@example.ie",
  ]) {
    assert.equal(validateEmail(ok), null, ok);
  }
});

test('email validation rejects shapes that cannot be an address', () => {
  for (const bad of ['', 'diver', 'diver@', '@example.com', 'diver@example', 'a b@example.com', 'a@b c.com']) {
    assert.notEqual(validateEmail(bad), null, JSON.stringify(bad));
  }
  assert.notEqual(validateEmail(`${'a'.repeat(MAX_EMAIL)}@example.com`), null);
});

test('a verification token is a credential, not a code', () => {
  // It travels through email and sits in an inbox, so it gets the same
  // treatment as a session token: unguessable, url-safe, stored hashed only.
  const seen = new Set<string>();
  for (let i = 0; i < 200; i++) {
    const v = newVerification();
    assert.match(v.token, /^[A-Za-z0-9_-]+$/, 'must survive being pasted into a URL');
    assert.ok(v.token.length >= 40, 'must carry real entropy');
    assert.equal(seen.has(v.token), false, 'collision');
    seen.add(v.token);
    assert.equal(v.tokenHash, hashToken(v.token));
    assert.notEqual(v.tokenHash, v.token, 'the raw token must never be what is stored');
  }
});

test('a verification link expires far sooner than a session', () => {
  const v = newVerification();
  const hours = (v.expiresAt.getTime() - Date.now()) / 3_600_000;
  // Within a second either side of the declared window.
  assert.ok(Math.abs(hours - VERIFY_HOURS) < 0.01, `got ${hours}h`);
  // A year-long session and a day-long link are different risks; if these ever
  // converge, a forwarded email becomes as good as a password.
  assert.ok(v.expiresAt.getTime() < newSession().expiresAt.getTime());
});
