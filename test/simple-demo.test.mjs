import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {scanText} from '../src/engine.mjs';
import {profile} from '../examples/simple-after.js';
test('simple demonstration shows exactly three review patterns, then zero',async()=>{
 const before=await readFile('examples/simple-before.js','utf8');
 const after=await readFile('examples/simple-after.js','utf8');
 assert.deepEqual(scanText(before,'simple-before.js').map(f=>f.ruleId),['DTG001','DTG004','DTG002']);
 assert.equal(scanText(after,'simple-after.js').length,0);
});
test('manual fix binds SQL, treats hostile markup as text and rejects injection IDs',async()=>{
 let query,args;const element={set innerHTML(v){assert.fail('HTML must never be interpreted');}};
 const name='<img src=x onerror=alert(1)>';
 await profile(JSON.stringify({id:'12',name}),{query:async(q,a)=>{query=q;args=a;return [];}},element);
 assert.equal(query,'SELECT display_name FROM users WHERE id=$1');assert.deepEqual(args,[12]);assert.equal(element.textContent,name);
 for(const id of ['1 OR 1=1','-2',12])await assert.rejects(profile(JSON.stringify({id,name}),{query(){assert.fail('Invalid ID reached database');}},element));
 await assert.rejects(profile('{bad json}',{},element));
});
