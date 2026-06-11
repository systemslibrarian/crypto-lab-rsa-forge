/**
 * pss-encode.ts — Pure-JS EMSA-PSS-Encode for visualization.
 *
 * Reproduces RFC 8017 §9.1.1 so the PSS diagram hover can show real
 * mHash, salt, H, DB, maskedDB, and EM values from the user's message.
 * The actual signature is still produced via WebCrypto.
 */

const HLEN = 32; // SHA-256
const SLEN = 32; // matches the panel's saltLength = 32

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(buf);
}

async function mgf1(seed: Uint8Array, maskLen: number): Promise<Uint8Array> {
  const blocks = Math.ceil(maskLen / HLEN);
  const out = new Uint8Array(blocks * HLEN);
  const input = new Uint8Array(seed.length + 4);
  input.set(seed, 0);
  for (let c = 0; c < blocks; c++) {
    input[seed.length]     = (c >>> 24) & 0xff;
    input[seed.length + 1] = (c >>> 16) & 0xff;
    input[seed.length + 2] = (c >>> 8)  & 0xff;
    input[seed.length + 3] =  c         & 0xff;
    const h = await sha256(input);
    out.set(h, c * HLEN);
  }
  return out.slice(0, maskLen);
}

export interface PssFields {
  emLen: number;
  zeros8: Uint8Array;
  mHash: Uint8Array;
  salt: Uint8Array;
  MPrime: Uint8Array;
  H: Uint8Array;
  ps: Uint8Array;
  separator: Uint8Array;
  saltDB: Uint8Array;
  DB: Uint8Array;
  dbMask: Uint8Array;
  maskedDB: Uint8Array;
  trailer: Uint8Array;
  EM: Uint8Array;
}

/** EMSA-PSS-Encode (RFC 8017 §9.1.1) with SHA-256, sLen=32, 2048-bit modulus. */
export async function pssEncode(message: Uint8Array, modBits = 2048): Promise<PssFields> {
  const emBits = modBits - 1;
  const emLen = Math.ceil(emBits / 8);

  const mHash = await sha256(message);

  const salt = new Uint8Array(SLEN);
  crypto.getRandomValues(salt);

  const zeros8 = new Uint8Array(8);

  const MPrime = new Uint8Array(8 + HLEN + SLEN);
  MPrime.set(zeros8, 0);
  MPrime.set(mHash, 8);
  MPrime.set(salt, 8 + HLEN);

  const H = await sha256(MPrime);

  const psLen = emLen - SLEN - HLEN - 2;
  const ps = new Uint8Array(psLen);
  const separator = new Uint8Array([0x01]);
  const saltDB = new Uint8Array(salt);

  const DB = new Uint8Array(emLen - HLEN - 1);
  // PS (zero) then 0x01 then salt
  DB[psLen] = 0x01;
  DB.set(salt, psLen + 1);

  const dbMask = await mgf1(H, emLen - HLEN - 1);
  const maskedDB = new Uint8Array(DB.length);
  for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];

  // Clear leftmost (8*emLen - emBits) bits of maskedDB
  const shift = 8 * emLen - emBits;
  if (shift > 0) maskedDB[0] &= 0xff >> shift;

  const trailer = new Uint8Array([0xbc]);

  const EM = new Uint8Array(emLen);
  EM.set(maskedDB, 0);
  EM.set(H, maskedDB.length);
  EM[emLen - 1] = 0xbc;

  return { emLen, zeros8, mHash, salt, MPrime, H, ps, separator, saltDB, DB, dbMask, maskedDB, trailer, EM };
}
