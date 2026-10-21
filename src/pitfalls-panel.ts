import { generateWebRsa } from './jwk.js';
import { crtSign, factorFromFaultySignature, factorFromKeyPair, commonModulusAttack, releaseSignature, oaepDecode } from './pitfalls.js';
import { modPow, gcd, modInverse, bitLen, generateRsaKeyPair, encodeMessage, decodeMessage } from './textbook.js';
import { bytesToBigint, bigintToBytes } from './ui.js';
import { oaepEncode } from './oaep-encode.js';
export const SHARED_NEGATIVE = "Each employee's key pair is valid on its own — e·d ≡ 1 mod φ(N) and the round trip succeeds — and any one of them still decrypts every colleague's mail.";
const el = <T extends HTMLElement>(id:string) => document.getElementById(id) as T;
export const escape = (s:unknown) => String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export const chip = (kind:'safe'|'warn'|'danger',s:string) => `<p class="status-chip status-chip-${kind}">${kind==='safe'?'✓':kind==='warn'?'⚠':'✗'} ${escape(s)}</p>`;
export function showValues(prefix:string,values:Record<string,unknown>) { el(prefix+'-values').innerHTML=Object.entries(values).map(([key,value])=>`<p><strong>${escape(key)}</strong><br><code class="crypto-value" id="${prefix}-${key}">${escape(value)}</code></p>`).join(''); }
const later = () => new Promise<void>(r=>setTimeout(r,0));
const setDisabled = (ids:string[],disabled:boolean) => ids.forEach(id=>{el<HTMLButtonElement>(id).disabled=disabled;});
const errorText = (e:unknown) => e instanceof Error?e.message:String(e);

export function initPitfallsPanel():void { initFault(); initShared(); initCommon(); }
function initFault():void {
  let key:Awaited<ReturnType<typeof generateWebRsa>>|undefined,s:bigint|undefined,EM:bigint|undefined,faulty:bigint|undefined,released:bigint|null=null;
  let revision=0,busy=false,correctVerified=false,faultVerified:boolean|null=null;
  let values:Record<string,unknown>={};
  const message=el<HTMLInputElement>('fault-message'),bit=el<HTMLInputElement>('fault-bit'),protect=el<HTMLInputElement>('fault-protect');
  bit.value=String(crypto.getRandomValues(new Uint32Array(1))[0]%1024);
  let oldMessage=message.value,oldBit=bit.value,oldProtect=protect.checked;
  function buttons(){setDisabled(['fault-generate'],busy);setDisabled(['fault-sign'],busy||!key);setDisabled(['fault-inject'],busy||s===undefined);setDisabled(['fault-factor'],busy||released===null);}
  function retire(all=false){revision++;busy=false;faulty=undefined;released=null;faultVerified=null;el('fault-result').replaceChildren();if(all){s=EM=undefined;correctVerified=false;}values=key?{N:key.parts.n,e:key.parts.e,p:key.parts.p,q:key.parts.q,...(!all&&s!==undefined?{s,EM}:{})}:{};showValues('fault',values);el('fault-status').textContent='Previous verdict retired. Run the current inputs.';buttons();}
  message.addEventListener('input',()=>{if(message.value!==oldMessage){oldMessage=message.value;retire(true);}});
  bit.addEventListener('input',()=>{if(bit.value!==oldBit){oldBit=bit.value;retire();}});
  protect.addEventListener('change',()=>{if(protect.checked!==oldProtect){oldProtect=protect.checked;retire();el('fault-mode').textContent=protect.checked?'Countermeasure ON: withhold any signature that fails verification.':'BROKEN MODE: release the faulty signature without checking it.';}});
  async function task(action:'generate'|'sign'|'inject'|'factor') {
    if(busy)return;const token=++revision;busy=true;buttons();el('fault-result').replaceChildren();el('fault-status').textContent='Computing with the current key…';
    try{
      if(action==='generate'){
        key=undefined;s=EM=faulty=undefined;released=null;correctVerified=false;faultVerified=null;values={};showValues('fault',values);
        const next=await generateWebRsa();if(token!==revision)return;key=next;values={N:key.parts.n,e:key.parts.e,p:key.parts.p,q:key.parts.q};bit.max=String(bitLen(key.parts.q)-1);el('fault-status').textContent='Fresh RSA-2048 key generated. Sign correctly next.';
      }else if(action==='sign'){
        const msg=new TextEncoder().encode(message.value);if(!message.value.trim())throw new Error('Enter a nonempty message.');
        const sig=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',key!.keys.privateKey,msg));
        const ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key!.keys.publicKey,sig,msg);if(token!==revision)return;
        s=bytesToBigint(sig);EM=modPow(s,key!.parts.e,key!.parts.n);const same=crtSign(EM,key!.parts)===s;correctVerified=ok&&same;released=null;faultVerified=null;
        if(!correctVerified)throw new Error('Correct-signature verification or CRT equality failed; attack refused.');
        Object.assign(values,{s,EM});el('fault-result').innerHTML=`<p id="fault-correct-check" data-state="pass">✓ WebCrypto verifies the correct signature; BigInt CRT equals it byte for byte.</p>`;el('fault-status').textContent='Correct signature verified. Choose a bit and inject the fault.';
      }else if(action==='inject'){
        if(!correctVerified)throw new Error('Sign and verify correctly first.');
        const selected=Number(bit.value);if(bit.value==='')throw new Error('Bit index must be 0–'+bit.max);
        const candidate=crtSign(EM!,key!.parts,{half:'q',bit:selected});
        const accepted=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key!.keys.publicKey,bigintToBytes(candidate,256) as BufferSource,new TextEncoder().encode(message.value));if(token!==revision)return;
        faulty=candidate;faultVerified=accepted;released=releaseSignature(key!.parts.n,key!.parts.e,EM!,faulty,protect.checked);
        Object.assign(values,{faulty,publicCheck:modPow(faulty,key!.parts.e,key!.parts.n),EM});
        el('fault-result').innerHTML=`<p id="fault-correct-check" data-state="${correctVerified?'pass':'fail'}">${correctVerified?'✓':'✗'} Correct signature verified.</p><p id="fault-bad-check" data-state="${accepted?'pass':'fail'}">${accepted?'✓':'✗'} WebCrypto ${accepted?'accepts':'rejects'} the faulty signature.</p>`+chip(released===null?'safe':'danger',released===null?'FAULTY SIGNATURE WITHHELD — verification protected the key':'BROKEN MODE — faulty signature released');
        el('fault-status').textContent=released===null?'Withheld: the attacker receives no signature.':'Released: the attacker can now use the public signature and message encoding.';
      }else{
        if(released===null||faultVerified!==false)throw new Error('No rejected, released faulty signature to attack.');
        const result=factorFromFaultySignature(key!.parts.n,key!.parts.e,EM!,released);
        const bellcore=gcd(s!-released,key!.parts.n),f=result.factors;
        const matches=!!f&&f.p===key!.parts.p&&f.q===key!.parts.q;
        Object.assign(values,{difference:result.difference,gcd:result.divisor,bellcore});
        el('fault-result').innerHTML=chip(matches?'danger':'warn',matches?'ONE FAULT — PRIVATE KEY FACTORED':'No factor from this pair')+`<p id="fault-jwk-check" data-state="${matches?'pass':'fail'}">${matches?'✓':'✗'} gcd = JWK p; N / gcd = JWK q; factors multiply to N and pass Miller–Rabin.</p><p>The faulty computation still agrees with the correct one modulo p. That makes the public difference a multiple of p, and the gcd exposes it.</p>`;
        el('fault-status').textContent=matches?'Attack complete: both factor routes agree.':'No nontrivial validated factor from this pair.';
      }
      if(token===revision)showValues('fault',values);
    }catch(e){if(token===revision){released=null;el('fault-status').textContent=errorText(e);}}
    finally{if(token===revision){busy=false;buttons();}}
  }
  for(const action of ['generate','sign','inject','factor'] as const)el('fault-'+action).addEventListener('click',()=>{void task(action);});
}

function initShared():void {
  let key:ReturnType<typeof generateRsaKeyPair>|undefined,eB=0n,dB=0n,cB=0n,recovered:ReturnType<typeof factorFromKeyPair>|undefined,busy=false;
  let values:Record<string,unknown>={};const plain='Private memo for B',m=encodeMessage(plain);
  function buttons(){setDisabled(['shared-issue'],busy);setDisabled(['shared-factor'],busy||!key);setDisabled(['shared-read'],busy||!recovered);}
  async function task(action:'issue'|'factor'|'read') {
    if(busy)return;busy=true;buttons();el('shared-result').replaceChildren();el('shared-status').textContent='Computing…';
    try{
      if(action==='issue'){
        key=undefined;recovered=undefined;values={};el('shared-checks').replaceChildren();showValues('shared',values);await later();
        key=generateRsaKeyPair(512);eB=3n;while(gcd(eB,key.phi)!==1n||eB===key.e)eB+=2n;dB=modInverse(eB,key.phi);cB=modPow(m,eB,key.n);
        const aIdentity=key.e*key.d%key.phi===1n,bIdentity=eB*dB%key.phi===1n,aRound=modPow(modPow(m,key.e,key.n),key.d,key.n)===m,bRound=modPow(cB,dB,key.n)===m;
        el('shared-checks').innerHTML=[['A-identity',aIdentity],['A-roundtrip',aRound],['B-identity',bIdentity],['B-roundtrip',bRound]].map(([name,ok])=>`<p id="shared-${name}" data-state="${ok?'pass':'fail'}">${ok?'✓ PASS':'✗ FAIL'} — employee ${name}</p>`).join('');
        values={N:key.n,phi:key.phi,eA:key.e,dA:key.d,eB,dB,message:m,cB};showValues('shared',values);
        if(!aIdentity||!bIdentity||!aRound||!bRound){key=undefined;throw new Error('Key validation failed; attack refused.');}
        el('shared-status').textContent='Both employees pass identity and round-trip checks. Give the attacker only A’s pair.';
      }else if(action==='factor'){
        await later();recovered=factorFromKeyPair(key!.n,key!.e,key!.d);
        Object.assign(values,{p:recovered.p,q:recovered.q,k:recovered.k,t:recovered.t,r:recovered.r,attempts:recovered.attempts.length,retryLog:recovered.attempts.map((a,i)=>`${i+1}: g=${a.g}; g^r=${a.initial}; root=${a.root??'none'}; factor=${a.factor??'none'}`).join('\n')});showValues('shared',values);
        el('shared-result').innerHTML=chip('danger','SHARED MODULUS FACTORED FROM A’S KEY PAIR');el('shared-status').textContent=`Factored after ${recovered.attempts.length} random bases. Both factors validated.`;
      }else{
        const dRecovered=modInverse(eB,(recovered!.p-1n)*(recovered!.q-1n)),read=modPow(cB,dRecovered,key!.n),ok=read===m&&modPow(read,eB,key!.n)===cB;
        Object.assign(values,{recoveredDB:dRecovered,recoveredMessage:read});showValues('shared',values);
        el('shared-result').innerHTML=chip(ok?'danger':'warn',ok?'VALID KEY — AND EVERY COLLEAGUE EXPOSED':'Recovered key did not decrypt the message')+`<p id="shared-mail">${escape(decodeMessage(read))}</p>`+(ok?`<p id="shared-negative" class="extension-negative">${escape(SHARED_NEGATIVE)}</p>`:'');
        el('shared-status').textContent=ok?'B’s mail decrypted and re-encrypted successfully using the factors obtained from A.':'Read failed; no recovery claimed.';
      }
    }catch(e){el('shared-status').textContent=errorText(e);}finally{busy=false;buttons();}
  }
  for(const action of ['issue','factor','read'] as const)el('shared-'+action).addEventListener('click',()=>{void task(action);});
}

function initCommon():void {
  const input=el<HTMLInputElement>('common-message');let previous=input.value,revision=0,busy=false;
  let current:{N:bigint;e1:bigint;e2:bigint;m:bigint;c1:bigint;c2:bigint;oaep1:bigint;oaep2:bigint;em1:bigint;em2:bigint}|undefined;
  let values:Record<string,unknown>={};
  function buttons(){setDisabled(['common-encrypt'],busy);setDisabled(['common-attack','common-oaep'],busy||!current);}
  input.addEventListener('input',()=>{if(input.value===previous)return;previous=input.value;revision++;busy=false;current=undefined;values={};el('common-result').replaceChildren();showValues('common',values);el('common-status').textContent='Previous verdict retired. Encrypt the edited message.';buttons();});
  async function task(action:'encrypt'|'attack'|'oaep'){
    if(busy)return;const token=++revision;busy=true;buttons();el('common-result').replaceChildren();el('common-status').textContent='Computing…';
    try{
      if(action==='encrypt'){
        current=undefined;values={};showValues('common',values);const message=input.value;
        if(!message.trim())throw new Error('Enter a nonempty message.');const bytes=new TextEncoder().encode(message);if(bytes.length>190)throw new Error('Maximum 190 UTF-8 bytes for RSA-2048 OAEP-SHA256.');
        const {parts:k}=await generateWebRsa();let e2=3n;const phi=(k.p-1n)*(k.q-1n);while(gcd(e2,phi)!==1n||gcd(k.e,e2)!==1n)e2+=2n;
        const a=await oaepEncode(bytes,256),b=await oaepEncode(bytes,256);if(token!==revision)return;
        const m=encodeMessage(message),em1=bytesToBigint(a.EM),em2=bytesToBigint(b.EM);
        current={N:k.n,e1:k.e,e2,m,c1:modPow(m,k.e,k.n),c2:modPow(m,e2,k.n),oaep1:modPow(em1,k.e,k.n),oaep2:modPow(em2,e2,k.n),em1,em2};values={...current};showValues('common',values);el('common-status').textContent='Two textbook ciphertexts and two independently OAEP-encoded ciphertexts ready.';
      }else{
        const c=current!,result=commonModulusAttack(c.N,c.e1,c.e2,action==='attack'?c.c1:c.oaep1,action==='attack'?c.c2:c.oaep2);
        Object.assign(values,{X:result.X,Y:result.Y,recovered:result.message??'noninvertible ciphertext',factor:result.factors?.p??'none'});
        if(result.factors){el('common-result').innerHTML=chip('danger','NONINVERTIBLE CIPHERTEXT — gcd exposed a validated factor');}
        else if(action==='attack'){
          const ok=result.message===c.m;el('common-result').innerHTML=chip(ok?'danger':'warn',ok?'PUBLIC CIPHERTEXTS — PLAINTEXT RECOVERED':'Attack did not recover the message')+`<p id="common-recovered-text">${escape(decodeMessage(result.message!))}</p><p id="common-bezout">X·e1 + Y·e2 = ${result.X*c.e1+result.Y*c.e2}</p>`;
        }else{
          let decodeError='',decoded:Uint8Array|undefined;try{decoded=await oaepDecode(bigintToBytes(result.message!,256));}catch(e){decodeError=errorText(e);}if(token!==revision)return;
          const differs=c.em1!==c.em2;el('common-result').innerHTML=chip(decodeError&&differs?'safe':'warn',decodeError&&differs?'ATTACK FAILED — the two encoded messages differ':'Inspect this unusual encoding result')+`<p id="common-oaep-check">${escape(decodeError||'Decoded bytes: '+Array.from(decoded??[]).join(','))}</p><p id="common-em-check">Independent encodings equal: ${!differs}</p>`;
        }
        if(token!==revision)return;showValues('common',values);el('common-status').textContent='Attack complete; result derived from the actual arithmetic and decoding checks.';
      }
    }catch(e){if(token===revision)el('common-status').textContent=errorText(e);}finally{if(token===revision){busy=false;buttons();}}
  }
  for(const action of ['encrypt','attack','oaep'] as const)el('common-'+action).addEventListener('click',()=>{void task(action);});
}
