/* Key-size guidance, wherever this repository states it.
 *
 * The page and the README were corrected to separate two different things:
 * SP 800-57 Part 1 Rev. 5 Table 2 is a STRENGTH rating (2048-bit RSA at 112
 * bits, 3072-bit at 128), while NIST IR 8547 is a SCHEDULE — RSA at any key
 * size deprecated after 2030 and disallowed after 2035. src/oaep.ts kept the
 * old shorthand, "NIST SP 800-57 Part 1 Rev. 5 — 2048-bit minimum, 3072+ for
 * long-term", which reads as though a bigger modulus buys more time.
 *
 * Source comments are not rendered, so no browser test reaches them; this
 * reads the files.
 */
import { readFileSync } from 'node:fs';
import { describe, it, expect } from 'vitest';

const read = (rel: string) => readFileSync(new URL(rel, import.meta.url), 'utf8');

const sources = {
  'src/oaep.ts': read('../src/oaep.ts'),
  'index.html': read('../index.html'),
  'README.md': read('../README.md'),
};

describe('RSA key-size guidance', () => {
  it('never offers a larger modulus as a way past the IR 8547 schedule', () => {
    for (const [name, text] of Object.entries(sources)) {
      expect(text, `${name} drops the "3072+ for long-term" shorthand`).not.toContain(
        '3072+ for long-term',
      );
      expect(text, `${name} drops the bare "2048-bit minimum, " shorthand`).not.toContain(
        '2048-bit minimum, 3072',
      );
    }
  });

  it('pairs the strength rating with the transition schedule everywhere it appears', () => {
    for (const [name, text] of Object.entries(sources)) {
      if (!text.includes('SP 800-57')) continue;
      expect(text, `${name} names IR 8547 alongside SP 800-57`).toContain('IR 8547');
      expect(text, `${name} gives the disallowed date`).toMatch(/2035/);
      expect(text, `${name} gives the deprecation date`).toMatch(/2030/);
    }
  });

  it('says the schedule applies at every key size', () => {
    expect(sources['src/oaep.ts']).toContain('RSA at ANY key size');
    expect(sources['index.html']).toContain('RSA at every key size');
  });
});
