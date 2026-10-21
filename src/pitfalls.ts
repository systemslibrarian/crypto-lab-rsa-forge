/** Inspectable RSA implementation pitfalls. Existing arithmetic is reused. */
import { modPow, gcd, extGcd, modInverse, bitLen, millerRabin } from './textbook.js';
import { bytesToBigint } from './ui.js';
import { mgf1 } from './oaep-encode.js';
import type { RsaParts } from './jwk.js';
export type CrtParts = Pick<RsaParts,'p'|'q'|'dp'|'dq'|'qi'>;
const mod = (x: bigint, n: bigint) => (x % n + n) % n;
export function crtSign(EM: bigint, key: CrtParts, fault?: { half:'p'|'q'; bit:number }): bigint {
  let sp = modPow(EM,key.dp,key.p), sq = modPow(EM,key.dq,key.q);
  if (fault) {
    const prime = fault.half === 'p' ? key.p : key.q;
    if (!Number.isInteger(fault.bit) || fault.bit < 0 || fault.bit >= bitLen(prime)) throw new Error(`Bit index must be 0–${bitLen(prime)-1}`);
    if (fault.half === 'p') sp ^= 1n << BigInt(fault.bit); else sq ^= 1n << BigInt(fault.bit);
  }
  return mod(sq + key.q * mod((sp-sq)*key.qi,key.p),key.p*key.q);
}
// [extension] point: randomized PSS encoding needs a separate fault experiment.
export function validateFactor(N: bigint, p: bigint): {p:bigint;q:bigint}|null {
  if (p <= 1n || p >= N || N % p !== 0n) return null;
  const q = N/p;
  return p*q === N && millerRabin(p) && millerRabin(q) ? {p,q} : null;
}
/** Joye–Lenstra–Quisquater (1999): only one faulty signature plus its EM. */
export function factorFromFaultySignature(N: bigint, e: bigint, EM: bigint, faulty: bigint) {
  const difference = mod(modPow(faulty,e,N)-EM,N), divisor = gcd(difference,N);
  return { difference, divisor, factors:validateFactor(N,divisor) };
}
export function releaseSignature(N: bigint, e: bigint, EM: bigint, faulty: bigint, verifyBeforeRelease = true): bigint|null {
  const verified = modPow(faulty,e,N) === EM;
  return !verifyBeforeRelease || verified ? faulty : null;
}
/** Uniform rejection sampling; the attack receives no p, q or phi. */
export function randomBelow(limit: bigint): bigint {
  if (limit <= 0n) throw new Error('Invalid random range');
  const bits = bitLen(limit-1n), bytes = new Uint8Array(Math.max(1,Math.ceil(bits/8)));
  for (;;) { crypto.getRandomValues(bytes); if (bits%8) bytes[0] &= (1 << (bits%8))-1; const n=bytesToBigint(bytes); if(n<limit)return n; }
}
export function factorFromKeyPair(N: bigint, e: bigint, d: bigint, draw = randomBelow, maxAttempts = 128) {
  const k = e*d-1n;
  if (N <= 3n || N%2n===0n || e<=1n || d<=0n || k<=0n || k%2n!==0n) throw new Error('Invalid RSA key-pair input');
  let r=k,t=0; while(r%2n===0n){r>>=1n;t++;}
  const attempts: {g:bigint;initial:bigint;root:bigint|null;factor:bigint|null}[]=[];
  for(let attempt=0;attempt<maxAttempts;attempt++) {
    const g=draw(N-3n)+2n;
    if(g<2n||g>N-2n)throw new Error('Random base outside 2…N−2');
    const direct=validateFactor(N,gcd(g,N));
    let x=modPow(g,r,N); const entry={g,initial:x,root:null as bigint|null,factor:null as bigint|null}; attempts.push(entry);
    if(direct){entry.factor=direct.p;return{...direct,k,r,t,attempts};}
    if(x===1n||x===N-1n)continue;
    for(let j=0;j<t;j++) {
      const y=x*x%N;
      if(y===1n) {
        const factors=validateFactor(N,gcd(x-1n,N)); entry.root=x;
        if(factors){entry.factor=factors.p;return{...factors,k,r,t,attempts};} break;
      }
      if(y===N-1n)break;
      x=y;
    }
  }
  throw new Error(`No non-trivial root after ${maxAttempts} random bases; retry.`);
}
export function commonModulusAttack(N: bigint,e1: bigint,e2: bigint,c1: bigint,c2: bigint) {
  if(N<=3n||e1<=1n||e2<=1n||c1<0n||c2<0n||c1>=N||c2>=N)throw new Error('Invalid public RSA input');
  const [g,X,Y]=extGcd(e1,e2); if(g!==1n)throw new Error('Exponents must be coprime: gcd(e1,e2) ≠ 1');
  for(const c of [c1,c2]) { const factors=validateFactor(N,gcd(c,N)); if(factors)return {X,Y,message:null,factors}; }
  const power=(c:bigint,a:bigint)=>a<0n?modPow(modInverse(c,N),-a,N):modPow(c,a,N);
  return {X,Y,message:power(c1,X)*power(c2,Y)%N,factors:null};
}
/** Strict empty-label OAEP-SHA256 decode for the common-modulus contrast. */
export async function oaepDecode(EM: Uint8Array): Promise<Uint8Array> {
  if(EM.length<66||EM[0]!==0)throw new Error('OAEP decoding failed: leading byte or length');
  const seed=EM.slice(1,33),db=EM.slice(33),seedMask=await mgf1(db,32);
  for(let i=0;i<32;i++)seed[i]^=seedMask[i];
  const mask=await mgf1(seed,db.length);for(let i=0;i<db.length;i++)db[i]^=mask[i];
  const expected=new Uint8Array(await crypto.subtle.digest('SHA-256',new Uint8Array(0)));
  let mismatch=0;for(let i=0;i<32;i++)mismatch|=db[i]^expected[i];
  if(mismatch)throw new Error('OAEP decoding failed: label hash');
  let i=32;while(i<db.length&&db[i]===0)i++;
  if(i===db.length||db[i]!==1)throw new Error('OAEP decoding failed: separator');
  return db.slice(i+1);
}
