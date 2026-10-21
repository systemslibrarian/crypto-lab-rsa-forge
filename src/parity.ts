import { modPow, modInverse, bitLen } from './textbook.js';
import { crtSign, type CrtParts } from './pitfalls.js';
export type ParityOracle = (ciphertext: bigint) => 0|1;
/** Deliberately BROKEN server: never returns the plaintext, only its low bit. */
export function makeParityOracle(N: bigint, privateValue: bigint|CrtParts): ParityOracle {
  const key = typeof privateValue === 'bigint' ? privateValue : { ...privateValue };
  return ciphertext => {
    if(ciphertext<0n||ciphertext>=N)throw new Error('Ciphertext outside RSA range');
    const plaintext=typeof key==='bigint'?modPow(ciphertext,key,N):crtSign(ciphertext,key);
    return Number(plaintext & 1n) as 0|1;
  };
}
export interface ParityStep {queries:number;ciphertext:bigint;bit:0|1;sum:bigint;modulus:bigint;knownLow:bigint;complete:boolean;verified:boolean}
/** K–L §12.5.3 halving variant. The attacker gets only public values and bits. */
export function* parityRecover(N: bigint,e: bigint,y: bigint,oracle: ParityOracle,onStep?: (step:ParityStep)=>void): Generator<ParityStep> {
  if(N<=3n||N%2n===0n||e<=1n||y<0n||y>=N)throw new Error('Invalid public RSA input');
  const bits=bitLen(N),halving=modPow(modInverse(2n,N),e,N);
  let ciphertext=y,sum=0n,queries=0;
  for(let i=0;i<bits;i++) {
    const bit=oracle(ciphertext);if(bit!==0&&bit!==1)throw new Error('Oracle must return one bit');
    sum+=BigInt(bit)<<BigInt(i);queries++;
    const modulus=1n<<BigInt(i+1),knownLow=((-N*sum)%modulus+modulus)%modulus;
    const complete=i+1===bits,verified=complete&&knownLow<N&&modPow(knownLow,e,N)===y;
    const step={queries,ciphertext,bit,sum,modulus,knownLow,complete,verified};onStep?.(step);yield step;
    ciphertext=ciphertext*halving%N;
  }
}
