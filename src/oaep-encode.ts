/**
 * oaep-encode.ts — Pure-JS OAEP-SHA256 encoder for visualization.
 *
 * WebCrypto does the real encryption end-to-end and never exposes the
 * intermediate OAEP fields. This module reproduces RFC 8017 §7.1.1
 * OAEP-Encode step-by-step so the diagram hover can show real bytes
 * (lHash, seed, dbMask, maskedSeed, maskedDB, etc.) for the user's input.
 *
 * The output EM is identical in structure to what WebCrypto feeds into
 * the modular exponentiation step.
 */

const HLEN = 32; // SHA-256

async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest('SHA-256', data as BufferSource);
  return new Uint8Array(buf);
}

/** MGF1 (RFC 8017 §B.2.1) with SHA-256. */
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

export interface OaepFields {
  /** Modulus byte length. */
  k: number;
  /** lHash = SHA-256("") for empty label. */
  lHash: Uint8Array;
  /** Zero-padding string. */
  ps: Uint8Array;
  /** 0x01 separator. */
  separator: Uint8Array;
  /** Message bytes. */
  M: Uint8Array;
  /** DB = lHash || PS || 0x01 || M. */
  DB: Uint8Array;
  /** Random seed. */
  seed: Uint8Array;
  /** dbMask = MGF1(seed, k − hLen − 1). */
  dbMask: Uint8Array;
  /** maskedDB = DB XOR dbMask. */
  maskedDB: Uint8Array;
  /** seedMask = MGF1(maskedDB, hLen). */
  seedMask: Uint8Array;
  /** maskedSeed = seed XOR seedMask. */
  maskedSeed: Uint8Array;
  /** EM = 0x00 || maskedSeed || maskedDB. */
  EM: Uint8Array;
}

/** OAEP-encode per RFC 8017 §7.1.1 with empty label and SHA-256. */
export async function oaepEncode(message: Uint8Array, k: number): Promise<OaepFields> {
  if (message.length > k - 2 * HLEN - 2) {
    throw new Error('message too long for OAEP');
  }

  const lHash = await sha256(new Uint8Array(0));

  const psLen = k - message.length - 2 * HLEN - 2;
  const ps = new Uint8Array(psLen); // all zero

  const separator = new Uint8Array([0x01]);

  const M = new Uint8Array(message);

  const DB = new Uint8Array(k - HLEN - 1);
  DB.set(lHash, 0);
  // ps already zero
  DB[HLEN + psLen] = 0x01;
  DB.set(M, HLEN + psLen + 1);

  const seed = new Uint8Array(HLEN);
  crypto.getRandomValues(seed);

  const dbMask = await mgf1(seed, k - HLEN - 1);
  const maskedDB = new Uint8Array(DB.length);
  for (let i = 0; i < DB.length; i++) maskedDB[i] = DB[i] ^ dbMask[i];

  const seedMask = await mgf1(maskedDB, HLEN);
  const maskedSeed = new Uint8Array(HLEN);
  for (let i = 0; i < HLEN; i++) maskedSeed[i] = seed[i] ^ seedMask[i];

  const EM = new Uint8Array(k);
  EM[0] = 0x00;
  EM.set(maskedSeed, 1);
  EM.set(maskedDB, 1 + HLEN);

  return { k, lHash, ps, separator, M, DB, seed, dbMask, maskedDB, seedMask, maskedSeed, EM };
}
