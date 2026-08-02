// Name moderation.
//
// Diver names, room names and creature nicknames are user-generated content
// shown to strangers, so this is a compliance control, not a nicety — it is
// what Guideline 1.2's "filter objectionable content" means for an app whose
// free-text fields are all names. It lives in its own module so it can be
// tested without standing up Express or a database. See
// src/__tests__/moderation.test.ts.

// ── normalisation ───────────────────────────────────────────────────────────
// Leetspeak folds to letters before matching so "b1tch" and "$hit" don't slip
// past the list; separators fold away too, which catches "f.u.c.k" spelled out.
const LEET: Record<string, string> = { '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's' };
const foldLeet = (s: string) => s.toLowerCase().replace(/[013457@$]/g, (c) => LEET[c]);
const collapse = (s: string) => foldLeet(s).replace(/[ ._-]+/g, '');

// "fuuuck" and "niiigger" defeat a plain substring list. Runs of three or more
// of the same letter squeeze to one; runs of two are left alone so ordinary
// doubles ("assess", "bassett") are unchanged and stay eligible for the
// SAFE_WORDS exemption below.
const squeezeRuns = (s: string) => s.replace(/(.)\1{2,}/g, '$1');

/**
 * The word bank, grouped by what each group is for.
 *
 * Two match strengths, because the strength has to fit the term:
 *
 *   anywhere — unambiguous terms that do not occur inside innocent names, so a
 *              substring hit is enough to reject.
 *   exact    — short or name-adjacent terms that live inside real names (ass in
 *              Cassandra, dick in Dickson, cock in Hitchcock, adolf in Adolfo);
 *              these reject only when a whole word — or the whole name with
 *              separators stripped — IS the term, never a substring.
 *
 * Grouping is for the humans editing it. Everything is flattened into two lists
 * before matching, so which group a term sits in changes nothing at runtime.
 */
const WORD_BANK = {
  profanity: {
    anywhere: [
      'fuck', 'shit', 'bitch', 'cunt', 'whore', 'slut', 'wanker', 'asshole', 'arsehole',
      'dickhead', 'jackass', 'dumbass', 'bullshit', 'motherfucker', 'cocksucker', 'pussy',
      'bollocks', 'jerkoff', 'bastard', 'douchebag', 'twatwaffle',
    ],
    exact: ['ass', 'arse', 'dick', 'cock', 'prick', 'tit', 'tits', 'cum', 'twat', 'piss', 'crap', 'wank'],
  },

  slurs: {
    anywhere: [
      'nigger', 'nigga', 'faggot', 'retard', 'kike', 'chink', 'wetback', 'raghead',
      'tranny', 'beaner', 'gook', 'towelhead', 'currymuncher', 'shemale', 'halfbreed',
    ],
    exact: ['fag', 'dyke', 'homo', 'coon', 'spic', 'paki', 'negro', 'spaz', 'mongoloid'],
  },

  // The group this filter was missing. Hateful reference is not profanity — it
  // contains no swear word at all — but it is the thing most likely to be
  // typed into a name field to upset people, and it was previously allowed.
  hate: {
    anywhere: [
      'hitler', 'nazi', 'holocaust', 'siegheil', 'heilhitler', 'whitepower', 'whitepride',
      'aryanbrother', 'bloodandsoil', 'himmler', 'goebbels', 'eichmann', 'kukluxklan',
      'gaschamber', 'masterrace', 'ethniccleansing', 'lynchmob',
      // Multi-word terms live here rather than in `exact`: once separators are
      // stripped they are long and unambiguous, and the exact tier only ever
      // sees one word at a time, so "the third reich" would slip past it.
      'thirdreich', 'binladen', 'polpot', 'islamicstate', 'alqaeda', 'daesh', '14words',
    ],
    // 'adolf' is exact, not anywhere, so Adolfo and Adolphus — real names people
    // actually have — still work, while a bare "Adolf" does not. Plain '88' is
    // left out because it is a birth year far more often than a dog whistle.
    exact: ['adolf', 'fuhrer', 'kkk', 'klan', '1488', 'stalin'],
  },

  sexual: {
    anywhere: [
      'blowjob', 'handjob', 'creampie', 'gangbang', 'bukkake', 'dildo', 'masturbat',
      'porn', 'hentai', 'incest', 'bestiality', 'ejaculat', 'orgasm', 'fleshlight',
      'buttplug', 'deepthroat',
    ],
    exact: ['anal', 'anus', 'penis', 'vagina', 'boobs', 'nude', 'sex', 'milf', 'bdsm', 'nsfw', 'horny'],
  },

  // Violence and self-harm. A focus app aimed partly at students should not
  // carry "kys" on a leaderboard.
  harm: {
    anywhere: ['rapist', 'pedophile', 'paedophile', 'childporn', 'molest', 'killyourself', 'selfharm'],
    exact: ['rape', 'kys', 'suicide', 'genocide', 'terrorist'],
  },
} as const;

const BLOCK_ANYWHERE = Object.values(WORD_BANK).flatMap((g) => g.anywhere as readonly string[]);
const BLOCK_EXACT = Object.values(WORD_BANK).flatMap((g) => g.exact as readonly string[]);

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
  // Added with the wider bank: each contains a term from the new groups.
  'therapy', 'grapes', 'drape', 'scrape', 'trapeze', 'sextant', 'sextet', 'saxon',
  'stalingrad', 'lynch', 'lynchburg', 'adolfo', 'adolphus', 'rudolf', 'randolph',
  'canal', 'banal', 'analogue', 'analog', 'analyse', 'analyze', 'manual', 'annual',
  'titan', 'titanic', 'titus', 'nudge', 'horning', 'thorny',
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
  // Checked with and without stretched letters: the squeezed form catches
  // "fuuuck", the plain form is what the exemption list was written against.
  const squeezed = squeezeRuns(checkable);
  if (BLOCK_ANYWHERE.some((t) => checkable.includes(t) || squeezed.includes(t))) return true;

  // The exact tier is checked against both the leet-folded form and the raw
  // one. Folding is what catches "a$$", but it also rewrites digits — '1488'
  // becomes 'ia88' and would never match itself — so numeric terms need the
  // unfolded text to compare against.
  const collapsed = collapse(raw);
  const rawWords = raw.toLowerCase().split(/[ ._-]+/).filter(Boolean);
  const rawCollapsed = rawWords.join('');
  return BLOCK_EXACT.some(
    (t) => collapsed === t || words.includes(t) || rawCollapsed === t || rawWords.includes(t)
  );
}
