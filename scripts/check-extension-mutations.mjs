// Concrete source mutations: baseline, built mutant, named failure, exact restoration.
import {readFileSync,writeFileSync,rmSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const cases=[
  {
    "name": "M1 countermeasure accepts any signature",
    "file": "src/pitfalls.ts",
    "anchor": "const verified = modPow(faulty,e,N) === EM;",
    "replacement": "const verified = true || modPow(faulty,e,N) === EM;",
    "test": "Tab 7: verify-before-release withholds"
  },
  {
    "name": "M2 faulty-signature gcd uses difference plus one",
    "file": "src/pitfalls.ts",
    "anchor": "gcd(difference,N)",
    "replacement": "gcd(difference+1n,N)",
    "test": "Tab 7: one released fault factors"
  },
  {
    "name": "M3 private-pair attack only accepts a trivial root",
    "file": "src/pitfalls.ts",
    "anchor": "if(y===1n) {\n        const factors=validateFactor(N,gcd(x-1n,N));",
    "replacement": "if(y===1n && x===1n) {\n        const factors=validateFactor(N,gcd(x+1n,N));",
    "test": "Tab 7: valid employee keys"
  },
  {
    "name": "M4 common-modulus Bezout powers swapped",
    "file": "src/pitfalls.ts",
    "anchor": "message:power(c1,X)*power(c2,Y)%N",
    "replacement": "message:power(c1,Y)*power(c2,X)%N",
    "test": "Tab 7: public Bezout arithmetic"
  },
  {
    "name": "M5 oracle returns ciphertext parity",
    "file": "src/parity.ts",
    "anchor": "return Number(plaintext & 1n) as 0|1;",
    "replacement": "return Number((ciphertext + 0n*plaintext) & 1n) as 0|1;",
    "test": "Tab 8: one-bit-only negative fixture"
  },
  {
    "name": "M6 query counter never increments",
    "file": "src/parity.ts",
    "anchor": "sum+=BigInt(bit)<<BigInt(i);queries++;",
    "replacement": "sum+=BigInt(bit)<<BigInt(i);queries+=0;",
    "test": "Tab 8: one-bit-only negative fixture"
  },
  {
    "name": "shared-modulus negative sentence removed",
    "file": "src/pitfalls-panel.ts",
    "anchor": "export const SHARED_NEGATIVE = \"Each employee's key pair is valid on its own \u2014 e\u00b7d \u2261 1 mod \u03c6(N) and the round trip succeeds \u2014 and any one of them still decrypts every colleague's mail.\";",
    "replacement": "export const SHARED_NEGATIVE = \"\";",
    "test": "Tab 7: valid employee keys"
  },
  {
    "name": "shared-modulus fixture reports failed round trip",
    "file": "src/pitfalls-panel.ts",
    "anchor": "aRound=modPow(modPow(m,key.e,key.n),key.d,key.n)===m",
    "replacement": "aRound=modPow(modPow(m,key.e,key.n),key.d,key.n)!==m",
    "test": "Tab 7: valid employee keys"
  },
  {
    "name": "parity negative sentence removed",
    "file": "src/parity-panel.ts",
    "anchor": "export const PARITY_NEGATIVE = 'The server never returns a plaintext, only one bit, and that is enough to decrypt everything it can be sent.';",
    "replacement": "export const PARITY_NEGATIVE = '';",
    "test": "Tab 8: one-bit-only negative fixture"
  },
  {
    "name": "parity fixture re-encryption check inverted",
    "file": "src/parity.ts",
    "anchor": "modPow(knownLow,e,N)===y",
    "replacement": "modPow(knownLow,e,N)!==y",
    "test": "Tab 8: one-bit-only negative fixture"
  }
];
const run=(command,args,extra={})=>{if(command==='npm'&&args[0]==='run'&&args[1]==='build')rmSync('dist',{recursive:true,force:true});const r=spawnSync(command,args,{encoding:'utf8',timeout:120000,env:{...process.env,CI:'1',...extra}});return {status:r.status,output:(r.stdout??'')+'\n'+(r.stderr??'')};};
function requirePass(r,label){if(r.status!==0)throw new Error(label+'\n'+r.output);}
// Hash the emitted entry and its referenced files. An unreferenced old artifact
// is not evidence of what a browser loaded; the owning test also checks module URLs.
const digest=data=>createHash('sha256').update(data).digest('hex');
function emitted(){const html=readFileSync('dist/index.html','utf8');const names=[...new Set([...html.matchAll(/\/assets\/([^"'\s]+\.(?:js|css))/g)].map(m=>m[1]))].sort();if(!names.some(n=>n.endsWith('.js')))throw new Error('No emitted JavaScript entry');return names;}
function assets(){return Object.fromEntries(emitted().filter(f=>f.endsWith('.js')).map(f=>[f,digest(readFileSync('dist/assets/'+f))]));}
const hash=()=>digest(JSON.stringify({'index.html':digest(readFileSync('dist/index.html')),...Object.fromEntries(emitted().map(f=>['assets/'+f,digest(readFileSync('dist/assets/'+f))]))}));
function owning(e){return run('npx',['playwright','test',...(process.env.PLAYWRIGHT_CONFIG?['--config',process.env.PLAYWRIGHT_CONFIG]:[]),'--project=chromium','e2e/claims.spec.ts','--grep',e.test,'--retries=0'],{MUTATION_ASSETS:JSON.stringify(assets())});}
const records=[];
for(const e of cases){
 const source=readFileSync(e.file,'utf8');if(source.split(e.anchor).length!==2)throw new Error(e.name+': ambiguous anchor');
 requirePass(run('npm',['run','build']),e.name+' baseline build');const baseline=hash(),before=owning(e);requirePass(before,e.name+' baseline test');if(!/1 passed/.test(before.output))throw new Error('Owning test did not run exactly once');
 let mutant='',sourceDiff='',failure,restoredGreen=false;
 try{
  writeFileSync(e.file,source.replace(e.anchor,e.replacement));sourceDiff=run('git',['diff','--',e.file]).output.trim();if(!sourceDiff)throw new Error('No source patch');
  requirePass(run('npm',['run','build']),e.name+' mutant build');mutant=hash();if(mutant===baseline)throw new Error('Mutation did not change build');failure=owning(e);
 }finally{
  writeFileSync(e.file,source);requirePass(run('npm',['run','build']),e.name+' restore build');if(hash()!==baseline)throw new Error('Build not byte-exact restored');
  const restored=owning(e);requirePass(restored,e.name+' restored test');restoredGreen=/1 passed/.test(restored.output);if(hash()!==baseline||readFileSync(e.file,'utf8')!==source)throw new Error('Restored owner changed source or build');
 }
 const assertionFailure=failure.status!==0&&/AssertionError|Error: expect\(|expect\(received\)|expect\(locator\)\.[A-Za-z]+\(expected\) failed/.test(failure.output)&&failure.output.includes(e.test)&&!failure.output.includes('MUTATION_ASSET_MISMATCH')&&!failure.output.includes('Process from config.webServer');
 if(!assertionFailure||!restoredGreen)throw new Error(e.name+' did not fail a named assertion\n'+failure.output);
 records.push({name:e.name,sourceDiff,baseline,mutant,owningTest:e.test,unit:!!e.unit,baselinePassed:true,mutantBuilt:true,assertionFailure,retries:0,servedAssetGuard:!e.unit,loadedModuleGuard:true,restoredGreen,restoredHash:hash(),failureEvidence:failure.output.slice(0,4500)});
 writeFileSync('mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
 console.log(e.name+': killed; exact build restored; owning test green');
}
writeFileSync('mutation-evidence.json',JSON.stringify(records,null,2)+'\n');
