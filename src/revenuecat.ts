/**
 * Interpreting RevenueCat webhook events.
 *
 * Deliberately pure: this file decides *what an event means* and nothing else,
 * so the decisions can be tested without a database or a network. The route in
 * index.ts does the writing.
 *
 * The client stays an optimistic UI — it still grants Pro locally the moment a
 * purchase returns, because waiting on a webhook round trip to light up a
 * paywall would feel broken. The difference is that the server now has its own
 * answer, validated against the receipt by RevenueCat, and the next sync
 * overwrites whatever the phone believed.
 */

/** Entitlement id configured in the RevenueCat dashboard. Must match purchases.ts. */
export const PRO_ENTITLEMENT = 'pro';

/**
 * Pearls granted per consumable product.
 *
 * Duplicated from `Reefie/src/data.ts` (PEARL_BUNDLES: pearls + bonus) rather
 * than shared, because the two run on different machines and the server must
 * not trust the client for how much a purchase is worth — that is the whole
 * point of validating server-side. The client's copy drives display; this one
 * drives what is actually credited. Keep them in step, and treat this file as
 * the authority if they ever disagree.
 */
export const PEARLS_BY_PRODUCT: Record<string, number> = {
  reefie_pearls_handful: 500,
  reefie_pearls_pouch: 1300,
  reefie_pearls_chest: 3300,
  reefie_pearls_haul: 8000,
  reefie_pearls_trove: 20000,
};

/** Product ids that grant Pro. Lifetime is called out because it never lapses. */
export const PRO_LIFETIME_PRODUCT = 'reefie_pro_lifetime';
export const PRO_SUBSCRIPTION_PRODUCTS = ['reefie_pro_monthly', 'reefie_pro_yearly'];

/** The subset of RevenueCat's event envelope this server reads. */
export type RcEvent = {
  type?: string;
  app_user_id?: string;
  original_app_user_id?: string;
  product_id?: string;
  entitlement_ids?: string[] | null;
  transaction_id?: string;
  original_transaction_id?: string;
  expiration_at_ms?: number | null;
  purchased_at_ms?: number | null;
};

export type Effect =
  /** Set the account's Pro state. `until` is null for lifetime or for "off". */
  | { kind: 'pro'; lifetime: boolean; until: Date | null }
  /** Credit a consumable exactly once, keyed on transactionId. */
  | { kind: 'pearls'; transactionId: string; productId: string; pearls: number }
  /** Nothing to do — recorded so the route can log why rather than guessing. */
  | { kind: 'ignore'; reason: string };

const grantsPro = (e: RcEvent) =>
  (e.entitlement_ids ?? []).includes(PRO_ENTITLEMENT) ||
  e.product_id === PRO_LIFETIME_PRODUCT ||
  PRO_SUBSCRIPTION_PRODUCTS.includes(e.product_id ?? '');

/**
 * What should this event change?
 *
 * The event types that matter, and why each is handled the way it is:
 *
 *  - INITIAL_PURCHASE / RENEWAL / PRODUCT_CHANGE / UNCANCELLATION → Pro on,
 *    until the expiry RevenueCat reports.
 *  - NON_RENEWING_PURCHASE → either the lifetime unlock or a pearl bundle.
 *  - EXPIRATION → Pro off. This is the one that actually ends access.
 *  - CANCELLATION → **deliberately does not revoke.** It means auto-renew was
 *    switched off, not that the period ended; the user has paid through to
 *    `expiration_at_ms` and taking Pro away early would be theft of something
 *    they bought. EXPIRATION arrives later and does the revoking.
 *  - BILLING_ISSUE → same reasoning. Apple retries billing for days, and
 *    dropping Pro on the first failed charge punishes an expired card.
 *  - TRANSFER → the purchase moved to another account. Ignored rather than
 *    guessed at: acting on a half-understood transfer could revoke Pro from
 *    someone who still owns it.
 */
export function effectOf(event: RcEvent): Effect {
  const type = (event.type ?? '').toUpperCase();

  switch (type) {
    case 'INITIAL_PURCHASE':
    case 'RENEWAL':
    case 'PRODUCT_CHANGE':
    case 'UNCANCELLATION': {
      if (!grantsPro(event)) return { kind: 'ignore', reason: `${type} for a non-Pro product` };
      return proEffect(event);
    }

    case 'NON_RENEWING_PURCHASE': {
      // Two very different things arrive as NON_RENEWING_PURCHASE: the lifetime
      // Pro unlock, and the five pearl consumables.
      if (event.product_id === PRO_LIFETIME_PRODUCT) {
        return { kind: 'pro', lifetime: true, until: null };
      }
      const pearls = PEARLS_BY_PRODUCT[event.product_id ?? ''];
      if (!pearls) return { kind: 'ignore', reason: `unknown product ${event.product_id}` };
      // No transaction id means no idempotency key, and crediting currency
      // without one risks paying out twice on a retry. Refuse instead.
      const transactionId = event.transaction_id ?? event.original_transaction_id;
      if (!transactionId) return { kind: 'ignore', reason: 'consumable with no transaction id' };
      return { kind: 'pearls', transactionId, productId: event.product_id!, pearls };
    }

    case 'EXPIRATION':
      return { kind: 'pro', lifetime: false, until: null };

    case 'CANCELLATION':
      return { kind: 'ignore', reason: 'cancellation only stops renewal; EXPIRATION ends access' };

    case 'BILLING_ISSUE':
      return { kind: 'ignore', reason: 'billing retries for days; EXPIRATION ends access' };

    case 'TRANSFER':
      return { kind: 'ignore', reason: 'transfer needs a human decision' };

    default:
      return { kind: 'ignore', reason: `unhandled event type ${type || '(none)'}` };
  }
}

function proEffect(event: RcEvent): Effect {
  if (event.product_id === PRO_LIFETIME_PRODUCT) return { kind: 'pro', lifetime: true, until: null };
  const ms = event.expiration_at_ms;
  // A subscription with no expiry is not something to guess at — granting
  // unbounded Pro on a malformed event is the expensive direction to be wrong in.
  if (!ms || !Number.isFinite(ms)) return { kind: 'ignore', reason: 'subscription event with no expiry' };
  return { kind: 'pro', lifetime: false, until: new Date(ms) };
}
