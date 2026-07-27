import test from 'node:test';
import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync, createHmac } from 'node:crypto';
import { verifyAppleIdentityToken, __resetAppleKeyCache } from '../appleToken.js';

/**
 * These tests mint tokens with a throwaway key pair and stub Apple's JWKS
 * endpoint, so the whole verifier runs for real — signature check included —
 * without touching the network.
 *
 * The forgery cases are the point. A verifier that accepts a valid token is
 * easy; one that rejects a token signed by the wrong key, issued for a
 * different app, or claiming "alg":"none" is the part that actually protects
 * an account.
 */

const BUNDLE = 'com.jeffchoy.reefie';
const KID = 'test-key-1';

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const other = generateKeyPairSync('rsa', { modulusLength: 2048 });

const b64url = (b: Buffer | string) =>
  Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function mintToken(
  claims: Record<string, unknown>,
  opts: { key?: any; kid?: string; alg?: string } = {}
) {
  const header = { alg: opts.alg ?? 'RS256', kid: opts.kid ?? KID, typ: 'JWT' };
  const h = b64url(JSON.stringify(header));
  const p = b64url(JSON.stringify(claims));
  if (header.alg === 'none') return `${h}.${p}.`;
  if (header.alg === 'HS256') {
    // Signed with the *public* key as an HMAC secret — the classic algorithm
    // confusion attack. A verifier that trusts the header's alg accepts this.
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }) as string;
    return `${h}.${p}.${b64url(createHmac('sha256', pubPem).update(`${h}.${p}`).digest())}`;
  }
  const signer = createSign('RSA-SHA256');
  signer.update(`${h}.${p}`);
  signer.end();
  return `${h}.${p}.${b64url(signer.sign(opts.key ?? privateKey))}`;
}

const validClaims = (over: Record<string, unknown> = {}) => ({
  iss: 'https://appleid.apple.com',
  aud: BUNDLE,
  sub: '001234.abcdef.0000',
  email: 'diver@privaterelay.appleid.com',
  email_verified: 'true',
  exp: Math.floor(Date.now() / 1000) + 600,
  iat: Math.floor(Date.now() / 1000),
  ...over,
});

// Stub Apple's key endpoint with our throwaway public key.
const realFetch = globalThis.fetch;
test.before(() => {
  const jwk = publicKey.export({ format: 'jwk' }) as any;
  globalThis.fetch = (async (url: any) => {
    assert.match(String(url), /appleid\.apple\.com\/auth\/keys/);
    return {
      ok: true,
      status: 200,
      json: async () => ({ keys: [{ ...jwk, kid: KID, alg: 'RS256', use: 'sig' }] }),
    };
  }) as any;
});
test.after(() => {
  globalThis.fetch = realFetch;
});
test.beforeEach(() => __resetAppleKeyCache());

test('a well-formed Apple token verifies and yields the identity', async () => {
  const id = await verifyAppleIdentityToken(mintToken(validClaims()), BUNDLE);
  assert.equal(id.sub, '001234.abcdef.0000');
  assert.equal(id.email, 'diver@privaterelay.appleid.com');
  assert.equal(id.emailVerified, true);
});

test('email_verified is normalised from both the string and boolean forms', async () => {
  // Apple sends this as a boolean in some flows and a string in others. The
  // string "false" is truthy in JS, so a missed normalisation here would mark
  // an unverified address as verified — and that is what gates account linking.
  for (const [sent, expected] of [
    ['true', true],
    [true, true],
    ['false', false],
    [false, false],
    [undefined, false],
  ] as const) {
    const id = await verifyAppleIdentityToken(mintToken(validClaims({ email_verified: sent })), BUNDLE);
    assert.equal(id.emailVerified, expected, `email_verified=${JSON.stringify(sent)}`);
  }
});

test('a token signed by the wrong key is rejected', async () => {
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims(), { key: other.privateKey }), BUNDLE),
    /signature is invalid/
  );
});

test('"alg":"none" is rejected', async () => {
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims(), { alg: 'none' }), BUNDLE),
    /Unexpected Apple token algorithm/
  );
});

test('algorithm confusion — HS256 signed with the public key — is rejected', async () => {
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims(), { alg: 'HS256' }), BUNDLE),
    /Unexpected Apple token algorithm/
  );
});

test('a token issued for a different app is rejected', async () => {
  // Without this check, a token minted for any other Apple app would sign its
  // holder into Reefie.
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims({ aud: 'com.someone.else' })), BUNDLE),
    /issued for a different app/
  );
});

test('a token from the wrong issuer is rejected', async () => {
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims({ iss: 'https://evil.example' })), BUNDLE),
    /wrong issuer/
  );
});

test('an expired token is rejected', async () => {
  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims({ exp: Math.floor(Date.now() / 1000) - 60 })), BUNDLE),
    /expired/
  );
});

test('a token with no subject is rejected', async () => {
  await assert.rejects(() => verifyAppleIdentityToken(mintToken(validClaims({ sub: '' })), BUNDLE), /no user id/);
});

test('malformed tokens are rejected rather than throwing something unhelpful', async () => {
  for (const bad of ['', 'not-a-token', 'a.b', 'a.b.c.d', 'aaa.bbb.ccc']) {
    await assert.rejects(() => verifyAppleIdentityToken(bad, BUNDLE), `input=${JSON.stringify(bad)}`);
  }
});

test('an unknown key id triggers exactly one refetch, then fails cleanly', async () => {
  let calls = 0;
  const jwk = publicKey.export({ format: 'jwk' }) as any;
  const saved = globalThis.fetch;
  globalThis.fetch = (async () => {
    calls++;
    return { ok: true, status: 200, json: async () => ({ keys: [{ ...jwk, kid: KID, alg: 'RS256' }] }) };
  }) as any;

  await assert.rejects(
    () => verifyAppleIdentityToken(mintToken(validClaims(), { kid: 'rotated-away' }), BUNDLE),
    /unrecognised key/
  );
  // One cold fetch plus one rotation refetch. More would mean a hot loop
  // against Apple on every forged token.
  assert.equal(calls, 2);
  globalThis.fetch = saved;
});

test('the second verification does not refetch the key set', async () => {
  let calls = 0;
  const jwk = publicKey.export({ format: 'jwk' }) as any;
  const saved = globalThis.fetch;
  globalThis.fetch = (async () => {
    calls++;
    return { ok: true, status: 200, json: async () => ({ keys: [{ ...jwk, kid: KID, alg: 'RS256' }] }) };
  }) as any;

  await verifyAppleIdentityToken(mintToken(validClaims()), BUNDLE);
  await verifyAppleIdentityToken(mintToken(validClaims()), BUNDLE);
  // Apple's availability must not sit in the critical path of every sign-in.
  assert.equal(calls, 1);
  globalThis.fetch = saved;
});
