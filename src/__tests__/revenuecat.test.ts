import test from 'node:test';
import assert from 'node:assert/strict';
import { effectOf, PEARLS_BY_PRODUCT, type RcEvent } from '../revenuecat.js';

/**
 * These decide who has paid for what, so the failure modes are money in both
 * directions: granting Pro to someone who has not paid, and taking it from
 * someone who has.
 */

const HOUR = 3_600_000;
const ev = (over: Partial<RcEvent>): RcEvent => ({
  app_user_id: 'acct-1',
  transaction_id: 'txn-1',
  ...over,
});

test('a new subscription grants Pro until the reported expiry', () => {
  const until = Date.now() + 30 * 24 * HOUR;
  const e = effectOf(ev({ type: 'INITIAL_PURCHASE', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'], expiration_at_ms: until }));
  assert.equal(e.kind, 'pro');
  assert.equal(e.kind === 'pro' && e.lifetime, false);
  assert.equal(e.kind === 'pro' && e.until?.getTime(), until);
});

test('a renewal extends Pro', () => {
  const until = Date.now() + 60 * 24 * HOUR;
  const e = effectOf(ev({ type: 'RENEWAL', product_id: 'reefie_pro_yearly', entitlement_ids: ['pro'], expiration_at_ms: until }));
  assert.equal(e.kind === 'pro' && e.until?.getTime(), until);
});

test('lifetime is a one-off that never lapses', () => {
  const e = effectOf(ev({ type: 'NON_RENEWING_PURCHASE', product_id: 'reefie_pro_lifetime' }));
  assert.equal(e.kind, 'pro');
  assert.equal(e.kind === 'pro' && e.lifetime, true);
  assert.equal(e.kind === 'pro' && e.until, null);
});

test('CANCELLATION does not revoke Pro', () => {
  // This is the one most likely to be got wrong. Cancellation means auto-renew
  // was switched off, not that the paid period ended — the user has paid
  // through to the expiry date. Revoking here takes away something they bought.
  const e = effectOf(ev({ type: 'CANCELLATION', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'], expiration_at_ms: Date.now() + 10 * 24 * HOUR }));
  assert.equal(e.kind, 'ignore');
});

test('BILLING_ISSUE does not revoke Pro', () => {
  // Apple retries billing for days. Dropping Pro on the first failed charge
  // punishes an expired card rather than a non-payer.
  const e = effectOf(ev({ type: 'BILLING_ISSUE', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'] }));
  assert.equal(e.kind, 'ignore');
});

test('EXPIRATION is what actually ends access', () => {
  const e = effectOf(ev({ type: 'EXPIRATION', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'] }));
  assert.equal(e.kind, 'pro');
  assert.equal(e.kind === 'pro' && e.lifetime, false);
  assert.equal(e.kind === 'pro' && e.until, null);
});

test('a subscription event with no expiry grants nothing', () => {
  // Granting unbounded Pro on a malformed event is the expensive direction to
  // be wrong in, so this fails closed.
  for (const expiration_at_ms of [undefined, null, NaN, 0]) {
    const e = effectOf(ev({ type: 'INITIAL_PURCHASE', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'], expiration_at_ms }));
    assert.equal(e.kind, 'ignore', `expiry=${expiration_at_ms}`);
  }
});

test('every pearl bundle credits its documented amount', () => {
  // Must match PEARL_BUNDLES in Reefie/src/data.ts — pearls + bonus.
  const expected: Record<string, number> = {
    reefie_pearls_handful: 500,
    reefie_pearls_pouch: 1300,
    reefie_pearls_chest: 3300,
    reefie_pearls_haul: 8000,
    reefie_pearls_trove: 20000,
  };
  assert.deepEqual(PEARLS_BY_PRODUCT, expected);
  for (const [product_id, pearls] of Object.entries(expected)) {
    const e = effectOf(ev({ type: 'NON_RENEWING_PURCHASE', product_id, transaction_id: 't-' + product_id }));
    assert.equal(e.kind, 'pearls', product_id);
    assert.equal(e.kind === 'pearls' && e.pearls, pearls, product_id);
    assert.equal(e.kind === 'pearls' && e.transactionId, 't-' + product_id);
  }
});

test('a consumable with no transaction id is refused', () => {
  // No transaction id means no idempotency key, and crediting currency without
  // one risks paying out twice on a retry.
  const e = effectOf({ type: 'NON_RENEWING_PURCHASE', product_id: 'reefie_pearls_chest', app_user_id: 'a' });
  assert.equal(e.kind, 'ignore');
});

test('an unknown product credits nothing', () => {
  const e = effectOf(ev({ type: 'NON_RENEWING_PURCHASE', product_id: 'reefie_pearls_infinite' }));
  assert.equal(e.kind, 'ignore');
});

test('a purchase that grants no Pro entitlement does not grant Pro', () => {
  const e = effectOf(ev({ type: 'INITIAL_PURCHASE', product_id: 'something_else', entitlement_ids: [], expiration_at_ms: Date.now() + HOUR }));
  assert.equal(e.kind, 'ignore');
});

test('TRANSFER and unknown event types are ignored rather than guessed at', () => {
  for (const type of ['TRANSFER', 'SUBSCRIBER_ALIAS', 'TEST', '', 'SOMETHING_NEW']) {
    assert.equal(effectOf(ev({ type, product_id: 'reefie_pro_monthly' })).kind, 'ignore', type);
  }
});

test('event type matching is case-insensitive', () => {
  const until = Date.now() + HOUR;
  const e = effectOf(ev({ type: 'initial_purchase', product_id: 'reefie_pro_monthly', entitlement_ids: ['pro'], expiration_at_ms: until }));
  assert.equal(e.kind, 'pro');
});
