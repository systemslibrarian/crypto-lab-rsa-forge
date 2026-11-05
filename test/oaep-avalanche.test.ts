import { describe, expect, it } from 'vitest';

import { flipOneBit } from '../src/oaep';

const popcount = (value: number): number => {
  let n = value;
  let bits = 0;
  while (n) {
    bits += n & 1;
    n >>>= 1;
  }
  return bits;
};

/**
 * The avalanche button is labelled "Flip one input bit" and the panel claims
 * that doing so flips roughly half the output bits. That is the avalanche
 * criterion, and it is a claim about a ONE-BIT input change.
 *
 * Nothing checked the one bit. Replacing `^= 0x01` with `^= 0xff` — a whole
 * byte — left every unit test and all 37 browser tests green, because the
 * avalanche counter test only asserts that the counter matches the bytes it
 * highlighted, which holds for either flip size. The input bytes are not
 * rendered, so no browser test can see this; it has to be checked here.
 */
describe('flipOneBit', () => {
  it('changes exactly one bit of exactly one byte', () => {
    for (let trial = 0; trial < 200; trial++) {
      const before = Uint8Array.from({ length: 12 }, (_, i) => (i * 37) & 0xff);
      const after = Uint8Array.from(before);
      const { index, bit } = flipOneBit(after);

      let changedBytes = 0;
      let changedBits = 0;
      for (let i = 0; i < before.length; i++) {
        const delta = before[i]! ^ after[i]!;
        if (delta !== 0) changedBytes++;
        changedBits += popcount(delta);
      }
      expect(changedBytes, `trial ${trial}`).toBe(1);
      expect(changedBits, `trial ${trial}`).toBe(1);
      expect(before[index]! ^ after[index]!).toBe(1 << bit);
    }
  });

  it('reaches every bit position and every byte over many draws', () => {
    // A helper that always flipped bit 0, or always byte 0, would satisfy the
    // test above. The claim is a uniform single-bit flip.
    const bits = new Set<number>();
    const indices = new Set<number>();
    for (let trial = 0; trial < 2000; trial++) {
      const bytes = new Uint8Array(8);
      const { index, bit } = flipOneBit(bytes);
      bits.add(bit);
      indices.add(index);
    }
    expect([...bits].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
    expect(indices.size).toBe(8);
  });

  it('is its own inverse', () => {
    const bytes = Uint8Array.from([0xa5, 0x5a, 0xff, 0x00]);
    const original = Uint8Array.from(bytes);
    const { index, bit } = flipOneBit(bytes);
    bytes[index] ^= 1 << bit;
    expect([...bytes]).toEqual([...original]);
  });
});
