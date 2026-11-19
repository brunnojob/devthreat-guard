#!/usr/bin/env node
import {readdir,readFile,lstat,writeFile,realpath} from 'node:fs/promises';
import {resolve,relative,sep} from 'node:path';
import {createHash} from 'node:crypto';
import {scanText,toSarif,extension,VERSION} from '../src/engine.mjs';
const args=process.argv.slice(2), opts={format:'text',failOn:'high',baseline:null,output:null,path:'.'};
const usage='Usage: node bin/devthreat-guard.mjs [path] [--format text|json|sarif|markdown] [--output file] [--fail-on critical|high|medium|none] [--baseline report.json]';
try {
 let positional=false;
 for(let i=0;i<args.length;i++) {
  const a=args[i];
  if(a==='--help'||a==='-h') {console.log(usage);process.exit(0);}
  if(a==='--version') {console.log(VERSION);process.exit(0);}
  if(['--format','--output','--fail-on','--baseline'].includes(a)) {
   const v=args[++i];if(!v||v.startsWith('--')) throw Error('Missing value for '+a);
   opts[{'--format':'format','--output':'output','--fail-on':'failOn','--baseline':'baseline'}[a]]=v;
  } else if(a.startsWith('-')||positional) throw Error('Unknown argument: '+a);
  else {opts.path=a;positional=true;}
 }
 if(!['text','json','sarif','markdown'].includes(opts.format)||!['critical','high','medium','none'].includes(opts.failOn)) throw Error('Invalid format or severity');
 const root=resolve(opts.path), info=await lstat(root);
 if(info.isSymbolicLink()) throw Error('Root symlinks are not scanned');
 const base=info.isDirectory()?await realpath(root):resolve(root,'..');
 const ignored=new Set(['.git','node_modules','vendor','dist','build','coverage','.venv','venv','__pycache__']);
 const supported=new Set(['js','mjs','cjs','ts','tsx','jsx','py','c','cpp','h','hpp','cc','json','yaml','yml','html','env','sh','bash','dockerfile','pem','key']);
 let exclusions=[];
 try {exclusions=JSON.parse(await readFile(resolve(base,'.devthreat.json'),'utf8')).exclude??[];} catch(e) {if(e.code!=='ENOENT') throw Error('Invalid .devthreat.json: '+e.message);}
 if(!Array.isArray(exclusions)||exclusions.some(x=>typeof x!=='string'||!x||x.includes('..')||x.startsWith('/'))) throw Error('exclude must contain relative file/directory prefixes');
 const files=[], skipped=[],errors=[];let visited=0;
 const outputPath=opts.output?resolve(opts.output):null,baselinePath=opts.baseline?resolve(opts.baseline):null;
 async function walk(p) {
  if(++visited>30000) throw Error('Entry limit exceeded (30000). Narrow the scan path.');
  const name=relative(base,p).split(sep).join('/');
  if(p===outputPath||p===baselinePath) {skipped.push({path:name,reason:'report file'});return;}
  if(exclusions.some(x=>name===x||name.startsWith(x.replace(/\/$/,'')+'/'))) {skipped.push({path:name,reason:'configured exclusion'});return;}
  let st;try {st=await lstat(p);} catch(e){errors.push({path:name,error:e.code});return;}
  if(st.isSymbolicLink()) {skipped.push({path:name,reason:'symlink'});return;}
  if(st.isDirectory()) {
   if(ignored.has(p.split(sep).pop())) {skipped.push({path:name,reason:'generated/vendor directory'});return;}
   let entries;try{entries=await readdir(p);}catch(e){errors.push({path:name,error:e.code});return;}
   for(const entry of entries.sort()) await walk(resolve(p,entry));
  } else if(st.isFile()) {
   if(!supported.has(extension(p))) {skipped.push({path:name,reason:'unsupported type'});return;}
   if(st.size>1024*1024) {skipped.push({path:name,reason:'over 1 MiB'});return;}
   try{const content=await readFile(p,'utf8');if(content.includes('\0')) {skipped.push({path:name,reason:'binary'});return;}files.push({path:name,content});}catch(e){errors.push({path:name,error:e.code});}
  }
 }
 await walk(root);
 const findings=files.flatMap(f=>scanText(f.content,f.path).map(finding=>({...finding,fingerprint:createHash('sha256').update([finding.path,finding.ruleId,finding.line,finding.column].join(':')).digest('hex')})));
 let accepted=new Set();
 if(opts.baseline) {
  const prior=JSON.parse(await readFile(opts.baseline,'utf8'));
  if(!Array.isArray(prior.findings)) throw Error('Baseline must be a DevThreat Guard JSON report');
  accepted=new Set(prior.findings.map(x=>x.fingerprint).filter(x=>typeof x==='string'));
 }
 const active=findings.filter(f=>!accepted.has(f.fingerprint));
 const result={tool:'DevThreat Guard',version:VERSION,scope:'Pattern checks only; zero findings is not proof of zero vulnerabilities.',coverage:{scanned:files.length,skipped,errors},findings:active,baselined:findings.length-active.length};
 let output;
 if(opts.format==='json') output=JSON.stringify(result,null,2);
 else if(opts.format==='sarif') {const sarif=toSarif(active);sarif.runs[0].invocations=[{executionSuccessful:errors.length===0&&files.length>0,toolExecutionNotifications:errors.map(e=>({level:'error',message:{text:e.path+': '+e.error}}))}];output=JSON.stringify(sarif,null,2);}
 else {const clean=s=>String(s).replace(/[\r\n|`<>]/g,'_');output=[`DevThreat Guard ${VERSION}`,result.scope,`Scanned: ${files.length}; skipped: ${skipped.length}; errors: ${errors.length}; baselined: ${result.baselined}`,`Findings: ${active.length}`,...active.map(f=>`${clean(f.path)}:${f.line}:${f.column} [${f.severity}] ${f.ruleId} ${f.title}\n  ${f.fix}`)].join('\n');if(opts.format==='markdown') output='# DevThreat Guard report\n\n'+output;}
 if(opts.output) await writeFile(opts.output,output+'\n');else console.log(output);
 const rank={critical:3,high:2,medium:1,none:99};
 process.exitCode=errors.length||files.length===0?2:active.some(f=>rank[f.severity]>=rank[opts.failOn])?1:0;
} catch(error) {console.error('DevThreat Guard: '+error.message+'\n'+usage);process.exitCode=2;}
