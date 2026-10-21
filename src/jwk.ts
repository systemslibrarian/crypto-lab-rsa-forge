import { bytesToBigint } from './ui.js';
export interface RsaParts { n: bigint; e: bigint; d: bigint; p: bigint; q: bigint; dp: bigint; dq: bigint; qi: bigint }
export function decodeJwkInteger(value: string): bigint {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error('Malformed base64url integer');
  return bytesToBigint(Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0)));
}
export function rsaParts(jwk: JsonWebKey): RsaParts {
  if (jwk.kty !== 'RSA') throw new Error('Expected RSA JWK');
  const result = {} as RsaParts;
  for (const field of ['n','e','d','p','q','dp','dq','qi'] as const) {
    if (!jwk[field]) throw new Error('Missing RSA field '+field);
    result[field] = decodeJwkInteger(jwk[field]!);
  }
  return result;
}
export async function generateWebRsa() {
  const keys = await crypto.subtle.generateKey({ name:'RSASSA-PKCS1-v1_5', modulusLength:2048, publicExponent:new Uint8Array([1,0,1]), hash:'SHA-256' },true,['sign','verify']);
  const jwk = await crypto.subtle.exportKey('jwk',keys.privateKey);
  return { keys, jwk, parts:rsaParts(jwk) };
}
