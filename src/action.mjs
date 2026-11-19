import {spawnSync} from 'node:child_process';
import {resolve,relative,isAbsolute,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {appendFileSync,realpathSync,existsSync,lstatSync} from 'node:fs';
const workspace=realpathSync(process.env.GITHUB_WORKSPACE||process.cwd());
function within(path){const full=resolve(workspace,path);const rel=relative(workspace,full);if(rel==='..'||rel.startsWith('..'+(process.platform==='win32'?'\\':'/'))||isAbsolute(rel))throw Error('Path must stay inside workspace');return full;}
let code=2;
try{
 const target=within(process.env.INPUT_PATH||'.');
 if(realpathSync(target)!==target)throw Error('Symlink scan targets are not supported');
 const args=[resolve(dirname(fileURLToPath(import.meta.url)),'../bin/devthreat-guard.mjs'),target,'--fail-on',process.env['INPUT_FAIL-ON']||'high','--format',process.env.INPUT_FORMAT||'text'];
 const output=process.env.INPUT_OUTPUT;
 if(output){const full=within(output);if(existsSync(full)||lstatSync(dirname(full)).isSymbolicLink()||realpathSync(dirname(full))!==dirname(full))throw Error('Report requires a new file under an existing non-symlink directory');args.push('--output',full);}
 const result=spawnSync(process.execPath,args,{cwd:workspace,stdio:'inherit',timeout:120000,shell:false});
 code=result.status??2;
 if(result.error)console.error('Scanner failed: '+result.error.message);
}catch(error){console.error('DevThreat Guard action: '+error.message);}
if(process.env.GITHUB_OUTPUT)appendFileSync(process.env.GITHUB_OUTPUT,`exit-code=${code}\n`);
process.exitCode=code;
