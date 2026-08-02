import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { isProfaneName } from '../moderation.js';

// Name moderation is the one content filter Reefie has, and Guideline 1.2 counts
// on it. The interesting property is not "does it catch swear words" but the
// balance: it has to catch deliberate evasion without rejecting real people's
// names. Both failure directions are user-visible and one of them is offensive.

describe('isProfaneName — rejects', () => {
  const bad = [
    'fuckface',
    'Shitlord',
    'bigbitch',
    'a cunt here',
  ];
  for (const name of bad) {
    test(`plain profanity: ${name}`, () => assert.equal(isProfaneName(name), true));
  }

  const evasions = [
    ['b1tch', 'digit 1 for i'],
    ['$hit', 'dollar for s'],
    ['f.u.c.k', 'dotted out'],
    ['f_u_c_k', 'underscored'],
    ['f-u-c-k', 'hyphenated'],
    ['sh1t', 'digit inside'],
    ['FUCK', 'shouted'],
    ['a$$', 'exact term, leetspoken'],
  ] as const;
  for (const [name, why] of evasions) {
    test(`evasion (${why}): ${name}`, () => assert.equal(isProfaneName(name), true));
  }

  // Stretched letters used to walk straight through the substring list.
  const stretched = ['fuuuck', 'shiiiit', 'niiigger', 'biiitch'] as const;
  for (const name of stretched) {
    test(`stretched letters: ${name}`, () => assert.equal(isProfaneName(name), true));
  }
});

// The group the filter was missing: offensive by reference, with no swear word
// in it at all. Every one of these was an allowed diver name before.
describe('isProfaneName — hate and extremism', () => {
  const bad = [
    'Adolf',
    'adolf hitler',
    'Hitler',
    'BigNazi',
    'sieg heil',
    'white power',
    'the third reich',
    '1488',
    'KKK',
    'Stalin',
    'Bin Laden',
  ];
  for (const name of bad) {
    test(`rejects: ${name}`, () => assert.equal(isProfaneName(name), true));
  }

  // 'adolf' is deliberately exact-tier so real names survive it.
  const innocent = [
    ['Adolfo', 'a name people actually have'],
    ['Rudolf', 'ditto'],
    ['Randolph', 'ditto'],
    ['Stalingrad', 'a place, not the man'],
    ['Lynch', 'a common surname'],
  ] as const;
  for (const [name, why] of innocent) {
    test(`allows ${name} (${why})`, () => assert.equal(isProfaneName(name), false));
  }
});

describe('isProfaneName — sexual content and self-harm', () => {
  const bad = ['pornstar', 'BigDildo', 'gangbang', 'kys', 'rape', 'a rapist', 'nsfw'];
  for (const name of bad) {
    test(`rejects: ${name}`, () => assert.equal(isProfaneName(name), true));
  }

  const innocent = [
    ['Analysis', 'contains "anal"'],
    ['Canal Diver', 'contains "anal"'],
    ['Grape', 'contains "rape"'],
    ['Sussex', 'contains "sex"'],
    ['Therapist', 'contains "rapist"'],
  ] as const;
  for (const [name, why] of innocent) {
    test(`allows ${name} (${why})`, () => assert.equal(isProfaneName(name), false));
  }
});

describe('isProfaneName — allows', () => {
  // The whole reason the list is split into two tiers. Each of these contains a
  // blocked term as a substring, and each is a name a real person might pick.
  const innocent = [
    ['Cassandra', 'contains "ass"'],
    ['Dickson', 'contains "dick"'],
    ['Hitchcock', 'contains "cock"'],
    ['Scunthorpe', 'the classic false positive'],
    ['Titan', 'contains "tit"'],
    ['Cumbria', 'contains "cum"'],
    ['Assisi', 'contains "ass"'],
    ['Homer', 'contains "homo"? no — but adjacent'],
    ['Prickett', 'contains "prick"'],
    ['Bassett', 'contains "ass"'],
  ] as const;
  for (const [name, why] of innocent) {
    test(`real name (${why}): ${name}`, () => assert.equal(isProfaneName(name), false));
  }

  const ordinary = ['Jeff', 'Reef Diver', 'deep_blue', 'ocean.kid', 'Marina-77', '海の人'];
  for (const name of ordinary) {
    test(`ordinary name: ${name}`, () => assert.equal(isProfaneName(name), false));
  }
});

describe('isProfaneName — the exemption list cannot be used as a carrier', () => {
  test('an exempt word alone is allowed', () => {
    assert.equal(isProfaneName('Scunthorpe'), false);
  });

  test('an exempt word does not launder a slur beside it', () => {
    assert.equal(isProfaneName('Scunthorpe cunt'), true);
  });

  test('a longer word merely starting with an exempt one is still checked', () => {
    assert.equal(isProfaneName('scunthorpecunt'), true);
  });
});

describe('isProfaneName — exact-match tier', () => {
  test('rejects the bare term on its own', () => {
    assert.equal(isProfaneName('ass'), true);
    assert.equal(isProfaneName('Dick'), true);
  });

  test('rejects it as a whole word among others', () => {
    assert.equal(isProfaneName('big ass diver'), true);
  });

  test('does not reject it as a substring of a longer word', () => {
    assert.equal(isProfaneName('Bassline'), false);
  });
});
