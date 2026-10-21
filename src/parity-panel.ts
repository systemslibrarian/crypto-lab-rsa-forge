import { makeParityOracle, parityRecover, type ParityStep } from './parity.js';
import { generateWebRsa } from './jwk.js';
import { generateRsaKeyPair, encodeMessage, decodeMessage, modPow, bitLen } from './textbook.js';
import { initByteRevealGrid, updateByteReveal } from './attacks.js';
import { chip, escape, showValues } from './pitfalls-panel.js';
export const PARITY_NEGATIVE = 'The server never returns a plaintext, only one bit, and that is enough to decrypt everything it can be sent.';
const el = <T extends HTMLElement>(id:string) => document.getElementById(id) as T;
export function initParityPanel():void {
  const size=el<HTMLSelectElement>('parity-size'),message=el<HTMLInputElement>('parity-message');
  let oldSize=size.value,oldMessage=message.value,revision=0,running=false,busy=false,complete=false;
  let N=0n,e=0n,y=0n,iterator:Generator<ParityStep>|undefined,last:ParityStep|undefined;let bits:number[]=[];
  function buttons(){el<HTMLButtonElement>('parity-setup').disabled=busy||running;for(const id of ['step','run'])el<HTMLButtonElement>('parity-'+id).disabled=busy||running||!iterator||complete;el<HTMLButtonElement>('parity-cancel').disabled=!running;}
  function retire(){revision++;running=busy=complete=false;iterator?.return(undefined);iterator=undefined;last=undefined;bits=[];N=e=y=0n;el('parity-result').replaceChildren();el('parity-bits').textContent='';el('parity-formula').textContent='';el('parity-count').textContent='0';el('parity-total').textContent='0';el('parity-known-count').textContent='0';initByteRevealGrid(0,'parity');showValues('parity',{});el('parity-status').textContent='Previous verdict retired. Setup the current inputs.';buttons();}
  size.addEventListener('change',()=>{if(size.value!==oldSize){oldSize=size.value;retire();}});message.addEventListener('input',()=>{if(message.value!==oldMessage){oldMessage=message.value;retire();}});
  el('parity-related').addEventListener('click',event=>{event.preventDefault();el<HTMLButtonElement>('tab-5').click();el('tab-5').focus();});
  el('parity-setup').addEventListener('click',async()=>{
    if(busy||running)return;retire();const token=revision,chosenSize=size.value,typed=message.value;busy=true;buttons();el('parity-status').textContent='Generating a fresh local server key…';
    try{
      if(!typed.trim())throw new Error('Enter a nonempty message.');await new Promise(r=>setTimeout(r,0));
      const key=chosenSize==='2048'?(await generateWebRsa()).parts:generateRsaKeyPair(512);if(token!==revision)return;
      const x=encodeMessage(typed);if(x>=key.n)throw new Error('Message is too large for this modulus; shorten it.');
      N=key.n;e=key.e;y=modPow(x,e,N);
      // Private material goes into the isolated server closure only. The
      // recovery generator receives four public/interface inputs, never x/d.
      const oracle=makeParityOracle(N,'dp' in key?key:key.d);iterator=parityRecover(N,e,y,oracle);
      initByteRevealGrid(Math.ceil(bitLen(N)/8),'parity');el('parity-total').textContent=String(bitLen(N));showValues('parity',{N,e,y});el('parity-status').textContent='BROKEN server ready. Step one query to start recovering low bits.';
    }catch(error){if(token===revision)el('parity-status').textContent=error instanceof Error?error.message:String(error);}finally{if(token===revision){busy=false;buttons();}}
  });
  function step():boolean {
    const next=iterator!.next();if(next.done)return false;last=next.value;bits.push(last.bit);complete=last.complete;
    el('parity-count').textContent=String(last.queries);el('parity-known-count').textContent=String(bits.length);el('parity-bits').textContent=bits.join(' ');
    el('parity-formula').textContent=`Low ${bits.length} bits = (−N × ${last.sum}) mod ${last.modulus} = ${last.knownLow}.`;
    const bytes=Math.ceil(bitLen(N)/8);updateByteReveal(last.knownLow,last.knownLow,bytes,'parity',complete?bytes*8:bits.length);
    if(complete){
      const ok=last.verified;
      el('parity-result').innerHTML=chip(ok?'danger':'warn',ok?'ONE BIT PER QUERY — PLAINTEXT RECOVERED':'RECOVERY FAILED — re-encryption did not match')+`<p id="parity-reencrypt" data-state="${ok?'pass':'fail'}">${ok?'✓ PASS':'✗ FAIL'}: recovered x raised to e equals the original y.</p>`+(ok?`<p id="parity-plaintext">${escape(decodeMessage(last.knownLow))}</p><p id="parity-negative" class="extension-negative">${escape(PARITY_NEGATIVE)}</p>`:'');
      showValues('parity',{N,e,y,recovered:last.knownLow,reencrypted:modPow(last.knownLow,e,N)});el('parity-status').textContent=ok?`Recovered with exactly ${last.queries} one-bit queries.`:'Completed queries, but verification failed; no plaintext claimed.';
    }else{el('parity-result').innerHTML=chip('warn',`PARTIAL — ${bits.length} low bits known; no plaintext claimed`);el('parity-status').textContent=`Partial recovery: ${bits.length} one-bit queries so far.`;}
    return !complete;
  }
  el('parity-step').addEventListener('click',()=>{if(!iterator||running||complete)return;step();buttons();});
  el('parity-run').addEventListener('click',async()=>{
    if(!iterator||running||complete)return;const token=revision;running=true;buttons();
    try{while(running&&token===revision&&!complete){for(let i=0;i<8&&!complete;i++)step();await new Promise(r=>setTimeout(r,0));}}
    catch(error){if(token===revision)el('parity-status').textContent=error instanceof Error?error.message:String(error);}
    finally{if(token===revision){running=false;buttons();}}
  });
  el('parity-cancel').addEventListener('click',()=>{if(!running||complete)return;revision++;running=false;el('parity-status').textContent=`Cancelled — partial: ${bits.length} bits recovered. No plaintext claimed.`;el('parity-result').innerHTML=chip('warn',`PARTIAL — ${bits.length} low bits; resume or setup a fresh server`);buttons();});
}
