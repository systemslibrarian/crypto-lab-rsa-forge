import { expect, test } from 'vitest';
import { modPow, bitLen, generateRsaKeyPair } from '../src/textbook.js';
import { makeParityOracle, parityRecover, type ParityOracle } from '../src/parity.js';
import { generateWebRsa } from '../src/jwk.js';

// Independent textbook doubling/interval route: different invariant and direction.
function doubling(N:bigint,e:bigint,y:bigint,oracle:ParityOracle):bigint{
  let low=0n,high=N,denominator=1n,c=y;const multiplier=modPow(2n,e,N);
  for(let i=0;i<bitLen(N)+1;i++){
    c=c*multiplier%N;const middle=low+high;low*=2n;high*=2n;denominator*=2n;
    if(oracle(c))low=middle;else high=middle;
  }
  const x=(low+denominator-1n)/denominator;expect(modPow(x,e,N)).toBe(y);return x;
}
test('512-bit parity halving agrees with independent doubling; exactly bitLength N queries',()=>{
  for(let i=0;i<5;i++){
    const k=generateRsaKeyPair(512),x=i===0?0n:i===1?k.n-1n:123456789n+BigInt(i),y=modPow(x,k.e,k.n),oracle=makeParityOracle(k.n,k.d);
    const steps=[...parityRecover(k.n,k.e,y,oracle)],last=steps.at(-1)!;
    expect(steps.length).toBe(bitLen(k.n));expect(last.queries).toBe(bitLen(k.n));expect(last.knownLow).toBe(x);expect(last.verified).toBe(true);
    for(const step of steps){expect([0,1]).toContain(step.bit);expect(step.knownLow).toBe(x%step.modulus);}
    expect(doubling(k.n,k.e,y,oracle)).toBe(x);
  }
},60_000);
test('real RSA-2048 CRT parity server gives 2048 bits and a re-encryption proof',async()=>{
  const {parts:k}=await generateWebRsa(),x=k.n/3n,y=modPow(x,k.e,k.n);let calls=0;
  const oracle=makeParityOracle(k.n,k),wrapped:ParityOracle=c=>{calls++;return oracle(c);};
  const steps=[...parityRecover(k.n,k.e,y,wrapped)];expect(calls).toBe(2048);expect(steps.at(-1)!.knownLow).toBe(x);expect(steps.at(-1)!.verified).toBe(true);
},120_000);
test('partial traversal is partial; malformed oracle values are refused',()=>{
  const k=generateRsaKeyPair(64),y=modPow(42n,k.e,k.n),iterator=parityRecover(k.n,k.e,y,makeParityOracle(k.n,k.d));
  for(let i=1;i<=16;i++){const step=iterator.next().value!;expect(step.queries).toBe(i);expect(step.complete).toBe(false);expect(step.verified).toBe(false);}
  iterator.return();expect(iterator.next().done).toBe(true);
  expect(()=>[...parityRecover(k.n,k.e,y,(()=>2) as unknown as ParityOracle)]).toThrow('one bit');
});
