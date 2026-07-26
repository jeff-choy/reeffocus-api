// Name moderation.
//
// Diver and room names are user-generated content shown to strangers, so this
// is a compliance control, not a nicety — it is what Guideline 1.2's "filter
// objectionable content" means for an app whose only free-text field is a name.
// It lives in its own module so it can be tested without standing up Express or
// a database. See src/__tests__/moderation.test.ts.

// ── name moderation ─────────────────────────────────────────────────────────
// Leetspeak folds to letters before matching so "b1tch" and "$hit" don't slip
// past the list; separators fold away too, which catches "f.u.c.k" spelled out.
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
const foldLeet = (s: string) => s.toLowerCase().replace(/[013457@$]/g, (c) => LEET[c]);
const collapse = (s: string) => foldLeet(s).replace(/[ ._-]+/g, '');

// Two tiers, because the matching strength has to fit the term:
//   BLOCK_ANYWHERE — unambiguous profanity/slurs that don't occur inside
//                    innocent names, so a substring hit is enough to reject.
//   BLOCK_EXACT    — short or name-adjacent terms that live inside real names
//                    (ass in Cassandra, dick in Dickson, cock in Hitchcock);
//                    these reject only when a whole word — or the whole name
//                    with separators stripped — IS the term, never a substring.
const BLOCK_ANYWHERE = [
  'fuck', 'shit', 'bitch', 'cunt', 'whore', 'slut', 'wanker', 'asshole', 'arsehole',
  'dickhead', 'jackass', 'dumbass', 'bullshit', 'motherfucker', 'cocksucker', 'pussy',
  'bollocks', 'jerkoff', 'nigger', 'nigga', 'faggot', 'retard', 'kike', 'chink',
  'wetback', 'raghead', 'tranny', 'beaner', 'gook',
];
const BLOCK_EXACT = [
  'ass', 'arse', 'dick', 'cock', 'prick', 'tit', 'tits', 'cum', 'fag', 'twat',
  'dyke', 'homo', 'coon', 'spic', 'paki', 'negro', 'spaz', 'piss',
];

// Ordinary words that happen to contain a BLOCK_ANYWHERE term. Substring
// matching cannot tell these from the real thing — "Scunthorpe" contains
// "cunt", and rejecting it is the textbook example of this filter class going
// wrong. Only whole words are matched here, so the escape hatch cannot be used
// as a carrier: "scunthorpe" is exempt, "scunthorpecunt" is a different word
// and is not.
const SAFE_WORDS = new Set([
  'scunthorpe', 'penistone', 'lightwater', 'clitheroe', 'sussex', 'essex', 'middlesex',
  'cockburn', 'cockfosters', 'shitake', 'shiitake', 'analysis', 'analyst', 'assassin',
  'assess', 'assets', 'assist', 'assign', 'bassett', 'basset', 'grape', 'therapist',
  'cumbria', 'cumbernauld', 'scunny',
]);

/**
 * True if the name should be rejected on content.
 *
 * Both failure directions are user-visible, and they are not symmetric: letting
 * a slur through puts it in front of strangers, while a false positive tells
 * someone their own name is unacceptable. Hence two tiers plus an exemption
 * list, rather than one substring sweep.
 */
export function isProfaneName(raw: string): boolean {
  const words = foldLeet(raw).split(/[ ._-]+/).filter(Boolean);

  // Drop exempt words before the substring pass, so an innocent word cannot
  // trigger a match — but keep every other word, so a name that merely *starts*
  // with an exempt word is still checked in full.
  const checkable = words.filter((w) => !SAFE_WORDS.has(w)).join('');
  if (BLOCK_ANYWHERE.some((t) => checkable.includes(t))) return true;

  const collapsed = collapse(raw);
  return BLOCK_EXACT.some((t) => collapsed === t || words.includes(t));
}
