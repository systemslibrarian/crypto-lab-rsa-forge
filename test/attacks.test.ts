import { describe, it, expect } from 'vitest';
import {
  intCubeRoot, crt3,
  pkcs1v15Pad, pkcs1v15Unpad, makePkcs1v15Oracle, bleichenbacherAttack,
} from '../src/attacks.js';
import {
  modPow, generateRsaKeyPair, encodeMessage, decodeMessage,
} from '../src/textbook.js';
import { bytesToBigint, bigintToBytes } from '../src/ui.js';

describe('intCubeRoot', () => {
  it('is exact on perfect cubes', () => {
    for (const x of [0n, 1n, 2n, 7n, 255n, 123456789n, (1n << 200n) + 3n]) {
      expect(intCubeRoot(x * x * x)).toBe(x);
    }
  });

  it('returns the floor on non-cubes', () => {
    expect(intCubeRoot(26n)).toBe(2n);   // 3^3 = 27
    expect(intCubeRoot(27n)).toBe(3n);
    expect(intCubeRoot(28n)).toBe(3n);
    const r = intCubeRoot(1_000_001n);
    expect(r * r * r).toBeLessThanOrEqual(1_000_001n);
    expect((r + 1n) ** 3n).toBeGreaterThan(1_000_001n);
  });

  it('rejects negatives', () => {
    expect(() => intCubeRoot(-8n)).toThrow();
  });
});

describe('crt3 — Chinese Remainder Theorem for 3 congruences', () => {
  it('satisfies all three congruences', () => {
    const x = crt3(2n, 3n, 3n, 5n, 2n, 7n);
    expect(x % 3n).toBe(2n);
    expect(x % 5n).toBe(3n);
    expect(x % 7n).toBe(2n);
    expect(x).toBeGreaterThanOrEqual(0n);
    expect(x).toBeLessThan(3n * 5n * 7n);
  });

  it('reconstructs m^3 for the Håstad setup', () => {
    // Three coprime moduli, all bigger than m^3? No — that is the point of CRT:
    // each n_i > m but n1·n2·n3 > m^3, so CRT recovers the true m^3.
    const m = 12345n;
    const n1 = 99991n * 99989n; // ~2^33
    const n2 = 99961n * 99971n;
    const n3 = 99929n * 99923n;
    const c1 = modPow(m, 3n, n1);
    const c2 = modPow(m, 3n, n2);
    const c3 = modPow(m, 3n, n3);
    const M3 = crt3(c1, n1, c2, n2, c3, n3);
    expect(M3).toBe(m * m * m);
    expect(intCubeRoot(M3)).toBe(m);
  });
});

describe('Håstad broadcast attack — end to end', () => {
  it('recovers the plaintext from 3 e=3 ciphertexts without any private key', () => {
    const keys = [
      generateRsaKeyPair(64, 3n),
      generateRsaKeyPair(64, 3n),
      generateRsaKeyPair(64, 3n),
    ];
    const message = 'Hi 3x!';
    const m = encodeMessage(message);
    // Ensure the message fits under every modulus.
    for (const k of keys) expect(m).toBeLessThan(k.n);

    const c1 = modPow(m, 3n, keys[0].n);
    const c2 = modPow(m, 3n, keys[1].n);
    const c3 = modPow(m, 3n, keys[2].n);

    const M3 = crt3(c1, keys[0].n, c2, keys[1].n, c3, keys[2].n);
    const recovered = intCubeRoot(M3);
    expect(recovered * recovered * recovered).toBe(M3); // perfect cube
    expect(recovered).toBe(m);
    expect(decodeMessage(recovered)).toBe(message);
  });

  it('does NOT recover the message when e is large (safe config)', () => {
    // With e=65537 the ciphertexts are m^65537, so CRT of them is not m^3 and
    // the cube root is not a perfect cube → attack fails, as the demo claims.
    const keys = [
      generateRsaKeyPair(256, 65537n),
      generateRsaKeyPair(256, 65537n),
      generateRsaKeyPair(256, 65537n),
    ];
    const m = encodeMessage('Hi 3x!');
    const c1 = modPow(m, 65537n, keys[0].n);
    const c2 = modPow(m, 65537n, keys[1].n);
    const c3 = modPow(m, 65537n, keys[2].n);
    const M3 = crt3(c1, keys[0].n, c2, keys[1].n, c3, keys[2].n);
    const guess = intCubeRoot(M3);
    expect(guess * guess * guess).not.toBe(M3); // not a perfect cube
    expect(guess).not.toBe(m);
  });
});

describe('PKCS#1 v1.5 padding (RFC 8017 §7.2)', () => {
  it('produces a conformant EM: 0x00 0x02 || PS(non-zero,>=8) || 0x00 || M', () => {
    const k = 32;
    const msg = new TextEncoder().encode('Hi!');
    const em = pkcs1v15Pad(msg, k);
    expect(em.length).toBe(k);
    expect(em[0]).toBe(0x00);
    expect(em[1]).toBe(0x02);
    // Find separator
    let sep = -1;
    for (let i = 2; i < k; i++) if (em[i] === 0x00) { sep = i; break; }
    expect(sep).toBeGreaterThanOrEqual(10);       // PS >= 8 bytes
    for (let i = 2; i < sep; i++) expect(em[i]).not.toBe(0x00); // PS non-zero
    expect(Array.from(em.slice(sep + 1))).toEqual(Array.from(msg));
  });

  it('round-trips pad → unpad', () => {
    const k = 24;
    for (const s of ['Hi!', 'abc', 'padme']) {
      const msg = new TextEncoder().encode(s);
      const out = pkcs1v15Unpad(pkcs1v15Pad(msg, k));
      expect(out).not.toBeNull();
      expect(new TextDecoder().decode(out!)).toBe(s);
    }
  });

  it('throws when the message is too long for >=8 bytes of PS', () => {
    expect(() => pkcs1v15Pad(new Uint8Array(30), 32)).toThrow();
  });

  it('unpad rejects wrong prefix and short padding', () => {
    expect(pkcs1v15Unpad(new Uint8Array([0x00, 0x01, 0xff, 0x00, 0x41]))).toBeNull();
    // Separator too early (PS < 8) must be rejected as non-conformant.
    const bad = new Uint8Array(20).fill(0xff);
    bad[0] = 0x00; bad[1] = 0x02; bad[5] = 0x00; // zero at index 5 → PS=3 bytes
    expect(pkcs1v15Unpad(bad)).toBeNull();
  });
});

describe('PKCS#1 v1.5 padding oracle', () => {
  it('accepts a genuine padded ciphertext and rejects a random one', () => {
    const kp = generateRsaKeyPair(128, 65537n);
    const k = Math.ceil(kp.n.toString(16).length / 2);
    const oracle = makePkcs1v15Oracle(kp.n, kp.d, k);

    const em = pkcs1v15Pad(new TextEncoder().encode('Hi!'), k);
    const c = modPow(bytesToBigint(em), kp.e, kp.n);
    expect(oracle(c)).toBe(true);

    // A random ciphertext is overwhelmingly non-conformant.
    let conformant = 0;
    for (let i = 1n; i <= 20n; i++) {
      if (oracle((c + i * 7919n) % kp.n)) conformant++;
    }
    expect(conformant).toBeLessThan(20);
  });
});

describe('Bleichenbacher attack — full interval narrowing', () => {
  it('recovers the exact padded plaintext from the oracle alone', () => {
    // Small modulus keeps the test fast but exercises the real algorithm.
    const kp = generateRsaKeyPair(128, 3n); // e=3 shrinks the s-search
    const k = Math.ceil(kp.n.toString(16).length / 2);
    const oracle = makePkcs1v15Oracle(kp.n, kp.d, k);

    const target = 'Hi!';
    const em = pkcs1v15Pad(new TextEncoder().encode(target), k);
    const mTrue = bytesToBigint(em);
    const c = modPow(mTrue, kp.e, kp.n);

    const { m, queries } = bleichenbacherAttack(c, kp.n, kp.e, k, oracle);
    expect(m).toBe(mTrue);
    expect(queries).toBeGreaterThan(0);

    const recovered = pkcs1v15Unpad(bigintToBytes(m, k));
    expect(recovered).not.toBeNull();
    expect(new TextDecoder().decode(recovered!)).toBe(target);
  }, 30_000);
});
