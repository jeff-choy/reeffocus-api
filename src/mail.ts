/**
 * Transactional email.
 *
 * Resend over its HTTP API rather than the `resend` npm package or an SMTP
 * client: it is one POST with a JSON body, so it costs no dependency, no
 * connection pool and no supply-chain surface — the same reasoning that put
 * scrypt in auth.ts instead of bcrypt.
 *
 * Mail goes out as `support@reefie.io`, from the reefie.io domain verified in
 * Resend.
 *
 * Sending address and support address are deliberately the same one. Resend
 * does not need a mailbox to send — delivery is authorised by the domain's
 * DKIM/SPF records, not by the local part existing — so a `noreply@` that
 * nobody reads would have worked just as well technically. It would also mean
 * every reply to a verification email vanished, and "reply to the email you
 * were sent" is what people actually do. Pointing the From at the one real
 * mailbox costs nothing and makes that work.
 *
 * The domain verification is the whole ballgame, and it is worth recording why
 * rather than treating it as setup trivia.
 *
 * Resend permits its shared `onboarding@resend.dev` address to deliver *only to
 * the email the Resend account was registered with*. That is not a reputation
 * caveat, it is a hard delivery rule — with it in place the developer receives
 * verification emails and every real user silently receives nothing, while
 * signup still appears to work, because confirmation is soft-gated. Precisely
 * the sort of failure quiet enough to reach production unnoticed.
 *
 * A free-provider address is not an alternative either: verification requires
 * publishing DKIM/SPF records in the sending domain's DNS, which nobody can do
 * for gmail.com, and Gmail's own DMARC policy instructs receivers to reject
 * such mail.
 *
 * The fallback below therefore stays deliberately broken-ish: it is the shared
 * address, so a deploy that forgets MAIL_FROM sends only to the account owner
 * rather than silently sending to nobody from a plausible-looking address.
 */

const RESEND_ENDPOINT = 'https://api.resend.com/emails';
const API_KEY = process.env.RESEND_API_KEY ?? '';
const FROM = process.env.MAIL_FROM ?? 'Reefie <onboarding@resend.dev>';

/** Is a real provider wired up? Reported by /api/health, not by feature routes. */
export const mailConfigured = !!API_KEY;

/**
 * Whether `sendMail` can be expected to succeed. Routes read *this*, not
 * `mailConfigured`, so the guard matches what sendMail actually does: with no
 * key it logs the message in development and throws in production. Checking
 * `mailConfigured` instead made "Resend" impossible to exercise on a laptop —
 * the route refused before reaching the code path that would have printed the
 * link.
 */
export const canSendMail = !!API_KEY || process.env.NODE_ENV !== 'production';

export type Mail = { to: string; subject: string; html: string; text: string };

/**
 * Sends, or throws. Callers decide whether a failure is fatal: signup treats it
 * as non-fatal (the account exists and verification can be re-sent), while an
 * explicit "resend" tap surfaces it, because there the send *is* the action.
 */
export async function sendMail(mail: Mail): Promise<void> {
  if (!API_KEY) {
    // No key configured. In development this is the normal case, and printing
    // the body is what makes the flow testable without a provider at all — the
    // verification link is in the text part, ready to paste into a browser.
    if (process.env.NODE_ENV !== 'production') {
      console.log(`\n── mail (not sent: no RESEND_API_KEY) ──\nto: ${mail.to}\n${mail.subject}\n\n${mail.text}\n───\n`);
      return;
    }
    throw new Error('No mail provider is configured.');
  }

  const res = await fetch(RESEND_ENDPOINT, {
    method: 'POST',
    headers: { Authorization: `Bearer ${API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: FROM, to: [mail.to], subject: mail.subject, html: mail.html, text: mail.text }),
  });

  if (!res.ok) {
    // Resend's error body names the cause (unverified domain, invalid address,
    // rate limit). Keep it for the logs; callers show their own wording.
    const detail = await res.text().catch(() => '');
    throw new Error(`Mail send failed (${res.status}): ${detail.slice(0, 300)}`);
  }
}

// ── templates ───────────────────────────────────────────────────────────────
// Inline styles and a table-free layout, because email clients are not
// browsers: Gmail strips <style> blocks, Outlook ignores flexbox, and anything
// clever degrades to unstyled text. The text/ part is not an afterthought —
// it's what a screen reader and a plain-text client actually read.

export function verificationEmail(name: string, link: string): Omit<Mail, 'to'> {
  return {
    subject: 'Confirm your email for Reefie',
    text: [
      `Hi ${name},`,
      '',
      'Confirm your email address to secure your Reefie account:',
      link,
      '',
      'The link works for 24 hours. If it expires, open Reefie and tap Resend.',
      '',
      "If you didn't create a Reefie account, you can ignore this — nothing will happen.",
    ].join('\n'),
    html: `
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;background:#0A2540;padding:32px 16px;">
  <div style="max-width:480px;margin:0 auto;background:#F0F7FA;border-radius:18px;padding:32px;">
    <h1 style="margin:0 0 8px;font-size:22px;color:#0A2540;">Confirm your email</h1>
    <p style="margin:0 0 20px;font-size:15px;line-height:22px;color:#3d5566;">
      Hi ${escapeHtml(name)} — confirming your address is what lets you get back
      into your reef if you ever lose this phone.
    </p>
    <a href="${escapeHtml(link)}"
       style="display:inline-block;background:#0A2540;color:#F0F7FA;text-decoration:none;
              font-weight:700;font-size:16px;padding:14px 28px;border-radius:999px;">
      Confirm email
    </a>
    <p style="margin:20px 0 0;font-size:13px;line-height:19px;color:#5b7484;">
      The link works for 24 hours. If it expires, open Reefie and tap Resend.
    </p>
    <p style="margin:12px 0 0;font-size:13px;line-height:19px;color:#5b7484;">
      If you didn't create a Reefie account, ignore this email — nothing will happen.
    </p>
  </div>
</div>`.trim(),
  };
}

/** Minimal, and only ever applied to values that reach an HTML attribute or body. */
function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}
