import { describe, it, expect } from 'vitest';
import { oaepEncode, mgf1 } from '../src/oaep-encode.js';
import { pssEncode } from '../src/pss-encode.js';

const HLEN = 32;

async function sha256(d: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', d as BufferSource));
}
function xor(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) out[i] = a[i] ^ b[i];
  return out;
}
function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

describe('MGF1 (RFC 8017 §B.2.1, SHA-256)', () => {
  it('is anchored to real SHA-256 (empty digest KAT)', async () => {
    // SHA-256("") = e3b0c442...b855 — a fixed, universally known vector.
    const empty = Buffer.from(await sha256(new Uint8Array(0))).toString('hex');
    expect(empty).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('matches a reproducible MGF1 vector', async () => {
    const out = await mgf1(new Uint8Array([0x01, 0x02, 0x03, 0x04]), 40);
    expect(Buffer.from(out).toString('hex')).toBe(
      'e25f9f0a2c2664632d1be5e2f25b2794c371091b61eb762ad98861da3a2221ee366dcb38806a930d',
    );
  });

  it('is deterministic and respects the requested length', async () => {
    const a = await mgf1(new Uint8Array([9, 9]), 70);
    const b = await mgf1(new Uint8Array([9, 9]), 70);
    expect(a.length).toBe(70);
    expect(eq(a, b)).toBe(true);
    // First 40 bytes of a longer mask equal a shorter mask (block structure).
    const short = await mgf1(new Uint8Array([9, 9]), 40);
    expect(eq(a.slice(0, 40), short)).toBe(true);
  });
});

describe('OAEP-Encode (RFC 8017 §7.1.1, SHA-256, empty label)', () => {
  it('emits EM of length k starting with 0x00', async () => {
    const k = 256;
    const f = await oaepEncode(new TextEncoder().encode('secret'), k);
    expect(f.EM.length).toBe(k);
    expect(f.EM[0]).toBe(0x00);
    expect(f.lHash.length).toBe(HLEN);
    // lHash must be SHA-256 of the empty label.
    expect(eq(f.lHash, await sha256(new Uint8Array(0)))).toBe(true);
    // DB = lHash || PS(zero) || 0x01 || M
    expect(eq(f.DB.slice(0, HLEN), f.lHash)).toBe(true);
    const sepIdx = f.DB.indexOf(0x01, HLEN);
    expect(sepIdx).toBeGreaterThanOrEqual(HLEN);
    for (let i = HLEN; i < sepIdx; i++) expect(f.DB[i]).toBe(0x00);
  });

  it('is invertible: OAEP-Decode recovers the message and consistency checks pass', async () => {
    // Implement RFC 8017 §7.1.2 decode from the emitted fields and confirm
    // the masking is self-consistent and the message comes back byte-for-byte.
    const k = 128;
    const message = new TextEncoder().encode('round-trip me');
    const f = await oaepEncode(message, k);

    // Split EM.
    const Y = f.EM[0];
    const maskedSeed = f.EM.slice(1, 1 + HLEN);
    const maskedDB = f.EM.slice(1 + HLEN);
    expect(Y).toBe(0x00);

    const seedMask = await mgf1(maskedDB, HLEN);
    const seed = xor(maskedSeed, seedMask);
    expect(eq(seed, f.seed)).toBe(true);

    const dbMask = await mgf1(seed, k - HLEN - 1);
    const DB = xor(maskedDB, dbMask);
    expect(eq(DB, f.DB)).toBe(true);

    // lHash' must equal SHA-256("").
    expect(eq(DB.slice(0, HLEN), await sha256(new Uint8Array(0)))).toBe(true);

    // Find 0x01 separator after the zero PS.
    let i = HLEN;
    while (i < DB.length && DB[i] === 0x00) i++;
    expect(DB[i]).toBe(0x01);
    const recovered = DB.slice(i + 1);
    expect(new TextDecoder().decode(recovered)).toBe('round-trip me');
  });

  it('randomises: two encodings of the same message differ (fresh seed)', async () => {
    const a = await oaepEncode(new TextEncoder().encode('x'), 128);
    const b = await oaepEncode(new TextEncoder().encode('x'), 128);
    expect(eq(a.EM, b.EM)).toBe(false);
  });

  it('rejects an over-long message', async () => {
    const k = 64; // max msg = k - 2*hLen - 2 = 64 - 66 < 0 → always too long
    await expect(oaepEncode(new Uint8Array(k), k)).rejects.toThrow();
  });
});

describe('EMSA-PSS-Encode (RFC 8017 §9.1.1, SHA-256, sLen=32)', () => {
  it('emits EM ending in the 0xbc trailer with H = Hash(M\')', async () => {
    const modBits = 2048;
    const message = new TextEncoder().encode('sign me');
    const f = await pssEncode(message, modBits);

    const emLen = Math.ceil((modBits - 1) / 8);
    expect(f.EM.length).toBe(emLen);
    expect(f.EM[emLen - 1]).toBe(0xbc);

    // mHash = SHA-256(M)
    expect(eq(f.mHash, await sha256(message))).toBe(true);
    // M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt ; H = SHA-256(M')
    const MPrime = new Uint8Array(8 + HLEN + f.salt.length);
    MPrime.set(f.mHash, 8);
    MPrime.set(f.salt, 8 + HLEN);
    expect(eq(f.H, await sha256(MPrime))).toBe(true);
    // H is stored in EM just before the trailer.
    expect(eq(f.EM.slice(emLen - HLEN - 1, emLen - 1), f.H)).toBe(true);
  });

  it('passes EMSA-PSS-Verify (RFC 8017 §9.1.2)', async () => {
    const modBits = 2048;
    const emBits = modBits - 1;
    const emLen = Math.ceil(emBits / 8);
    const message = new TextEncoder().encode('verify me');
    const f = await pssEncode(message, modBits);
    const EM = f.EM;

    expect(EM[emLen - 1]).toBe(0xbc);
    const maskedDB = EM.slice(0, emLen - HLEN - 1);
    const H = EM.slice(emLen - HLEN - 1, emLen - 1);

    // Leftmost 8*emLen - emBits bits of maskedDB must be zero.
    const shift = 8 * emLen - emBits;
    if (shift > 0) expect(maskedDB[0] & (0xff << (8 - shift))).toBe(0);

    const dbMask = await mgf1(H, emLen - HLEN - 1);
    const DB = xor(maskedDB, dbMask);
    DB[0] &= 0xff >> shift; // clear leftmost bits per spec

    // DB = PS(0x00..) || 0x01 || salt
    const sLen = 32;
    const psLen = emLen - sLen - HLEN - 2;
    for (let i = 0; i < psLen; i++) expect(DB[i]).toBe(0x00);
    expect(DB[psLen]).toBe(0x01);
    const salt = DB.slice(DB.length - sLen);

    const MPrime = new Uint8Array(8 + HLEN + sLen);
    MPrime.set(await sha256(message), 8);
    MPrime.set(salt, 8 + HLEN);
    const Hprime = await sha256(MPrime);
    expect(eq(Hprime, H)).toBe(true);
  });

  it('rejects a tampered signature (forgery is not verifiable)', async () => {
    const modBits = 2048;
    const emBits = modBits - 1;
    const emLen = Math.ceil(emBits / 8);
    const f = await pssEncode(new TextEncoder().encode('genuine'), modBits);
    const EM = Uint8Array.from(f.EM);
    // Flip a byte inside H: verification must fail.
    EM[emLen - 10] ^= 0xff;

    const maskedDB = EM.slice(0, emLen - HLEN - 1);
    const H = EM.slice(emLen - HLEN - 1, emLen - 1);
    const shift = 8 * emLen - emBits;
    const dbMask = await mgf1(H, emLen - HLEN - 1);
    const DB = xor(maskedDB, dbMask);
    DB[0] &= 0xff >> shift;
    const sLen = 32;
    const salt = DB.slice(DB.length - sLen);
    const MPrime = new Uint8Array(8 + HLEN + sLen);
    MPrime.set(await sha256(new TextEncoder().encode('genuine')), 8);
    MPrime.set(salt, 8 + HLEN);
    const Hprime = await sha256(MPrime);
    expect(eq(Hprime, H)).toBe(false); // forgery rejected
  });
});
