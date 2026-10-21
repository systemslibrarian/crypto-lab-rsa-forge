import { expect, test } from 'vitest';
import { generateWebRsa } from '../src/jwk.js';
import { modPow, modInverse, gcd, bitLen, generateRsaKeyPair } from '../src/textbook.js';
import { bigintToBytes, bytesToBigint } from '../src/ui.js';
import { crtSign, factorFromFaultySignature, factorFromKeyPair, commonModulusAttack, releaseSignature, oaepDecode } from '../src/pitfalls.js';
import { oaepEncode } from '../src/oaep-encode.js';

test('WebCrypto RSA-2048 signature and both faulty CRT halves produce independently validated factors', async () => {
  for(let run=0;run<3;run++){
    const {keys,parts:k}=await generateWebRsa();const msg=new TextEncoder().encode('CRT fault teaching '+run);
    const sig=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',keys.privateKey,msg));
    expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',keys.publicKey,sig,msg)).toBe(true);
    const s=bytesToBigint(sig),EM=modPow(s,k.e,k.n);expect(crtSign(EM,k)).toBe(s);
    for(const half of ['p','q'] as const)for(const bit of [0,511,1023]){
      const fault=crtSign(EM,k,{half,bit});expect(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',keys.publicKey,bigintToBytes(fault,256),msg)).toBe(false);
      const f=factorFromFaultySignature(k.n,k.e,EM,fault);expect(f.factors?.p).toBe(half==='q'?k.p:k.q);expect(f.factors!.p*f.factors!.q).toBe(k.n);expect(gcd(s-fault,k.n)).toBe(f.divisor);
      expect(releaseSignature(k.n,k.e,EM,fault)).toBeNull();expect(releaseSignature(k.n,k.e,EM,fault,false)).toBe(fault);
    }
    expect(releaseSignature(k.n,k.e,EM,s)).toBe(s);expect(factorFromFaultySignature(k.n,k.e,EM,s).factors).toBeNull();
    expect(()=>crtSign(EM,k,{half:'q',bit:bitLen(k.q)})).toThrow('Bit index');
  }
},60_000);
test('one private key pair factors 50 random RSA moduli without p or q input',()=>{
  for(let i=0;i<50;i++){
    const k=generateRsaKeyPair(512),f=factorFromKeyPair(k.n,k.e,k.d);
    expect(f.p*f.q).toBe(k.n);expect([k.p,k.q]).toContain(f.p);expect(f.k).toBe((1n<<BigInt(f.t))*f.r);
    if(f.attempts.at(-1)!.root!==null){const root=f.attempts.at(-1)!.root!;expect(root*root%k.n).toBe(1n);expect([1n,k.n-1n]).not.toContain(root);}
  }
},60_000);
test('a private exponent valid modulo lambda but not phi still exposes the shared modulus',()=>{
  // RFC 8017 permits ed = 1 mod lambda(N); ed - 1 need not be a multiple of phi(N).
  const N=3233n,e=17n,d=413n,lambda=780n,phi=3120n;
  expect((e*d-1n)%lambda).toBe(0n);expect((e*d-1n)%phi).not.toBe(0n);
  // Exhaustively verify this small key, including messages that are not units.
  for(let m=0n;m<N;m++)expect(modPow(modPow(m,e,N),d,N)).toBe(m);
  const f=factorFromKeyPair(N,e,d,()=>1n,1); // fixed base g=3: 3^1755 = 182, 182^2 = 794, 794^2 = 1 mod N
  expect([f.p,f.q].sort((a,b)=>a<b?-1:1)).toEqual([53n,61n]);
  expect(f.p*f.q).toBe(N);expect(f.attempts[0].root).toBe(794n);
});
test('unsuccessful random bases are retried and counted; bounded failure is honest',()=>{
  const N=61n*53n,e=17n,d=2753n;
  // g=N-2 has a trivial sequence here; enumerate a proven non-factor base.
  let bad=0n;for(let n=0n;n<N-3n;n++){try{factorFromKeyPair(N,e,d,()=>n,1);}catch{bad=n;break;}}
  let count=0;const f=factorFromKeyPair(N,e,d,limit=>count++===0?bad:BigInt(count)%limit);
  expect(f.attempts.length).toBeGreaterThan(1);expect(f.p*f.q).toBe(N);
  expect(()=>factorFromKeyPair(N,e,d,()=>bad,2)).toThrow('No non-trivial root after 2');
});
test('common modulus uses signed Bezout coefficients and reports noninvertible factors',()=>{
  const N=61n*53n,m=42n,e1=17n,e2=65537n,a=commonModulusAttack(N,e1,e2,modPow(m,e1,N),modPow(m,e2,N));
  expect(a.X*e1+a.Y*e2).toBe(1n);expect(a.X<0n||a.Y<0n).toBe(true);expect(a.message).toBe(m);
  expect(()=>commonModulusAttack(N,6n,9n,3n,4n)).toThrow('coprime');
  const f=commonModulusAttack(N,e1,e2,modPow(61n,e1,N),modPow(61n,e2,N));expect(f.factors!.p*f.factors!.q).toBe(N);expect(f.message).toBeNull();
});
test('fresh OAEP encodings defeat common-modulus recipe; reusing one encoding does not',async()=>{
  const {parts:k}=await generateWebRsa();let e2=3n;const phi=(k.p-1n)*(k.q-1n);while(gcd(e2,phi)!==1n||gcd(e2,k.e)!==1n)e2+=2n;
  const msg=new TextEncoder().encode('same message'),a=await oaepEncode(msg,256),b=await oaepEncode(msg,256);
  expect(a.EM).not.toEqual(b.EM);expect(await oaepDecode(a.EM)).toEqual(msg);expect(await oaepDecode(b.EM)).toEqual(msg);
  const c1=modPow(bytesToBigint(a.EM),k.e,k.n),c2=modPow(bytesToBigint(b.EM),e2,k.n);
  const attack=commonModulusAttack(k.n,k.e,e2,c1,c2);expect(attack.message).not.toBe(bytesToBigint(a.EM));await expect(oaepDecode(bigintToBytes(attack.message!,256))).rejects.toThrow('OAEP');
  const reuse=commonModulusAttack(k.n,k.e,e2,c1,modPow(bytesToBigint(a.EM),e2,k.n));expect(await oaepDecode(bigintToBytes(reuse.message!,256))).toEqual(msg);
  expect(modPow(c2,modInverse(e2,phi),k.n)).toBe(bytesToBigint(b.EM));
},30_000);
