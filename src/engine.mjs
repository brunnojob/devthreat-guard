/** Deterministic pattern checks, NOT a parser, taint engine, CVE feed or runtime firewall. */
export const VERSION = '1.0.0';
const r = (id,title,severity,cwe,extensions,pattern,fix,confidence='medium') => ({id,title,severity,cwe,extensions,pattern,fix,confidence});
export const rules = [
 r('DTG001','Dynamic code execution','high','CWE-95',['js','mjs','cjs','ts','jsx','tsx','py'],/(?<![\w.])(?:eval|exec)\s*\(/,'Replace dynamic execution with a constrained parser or an explicit operation map.'),
 r('DTG002','HTML injection sink','high','CWE-79',['js','mjs','ts','jsx','tsx','html'],/\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|dangerouslySetInnerHTML/,'Use textContent for text. For necessary rich HTML, use a maintained sanitizer and a restrictive CSP.'),
 r('DTG003','Shell command execution','high','CWE-78',['py','js','mjs','ts'],/\bos\.system\s*\(|\bshell\s*=\s*True|\bexecSync\s*\(|\bchild_process\.exec\s*\(/,'Use an allowlisted executable and an argument array with shell disabled. Validate arguments.'),
 r('DTG004','SQL query interpolation','high','CWE-89',['py','js','mjs','ts'],/\b(?:execute|query)\s*\(\s*(?:f["']|`[^`]*\$\{|["'][^"']*["']\s*\+)/,'Use driver-bound query parameters. Do not interpolate values or identifiers from requests.'),
 r('DTG005','TLS certificate validation disabled','high','CWE-295',['py','js','mjs','ts','json','yaml','yml'],/\bverify\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[:=]\s*["']?0/,'Enable certificate and hostname validation. Configure a trusted CA for private services.','high'),
 r('DTG006','Unsafe Python deserialization','high','CWE-502',['py'],/\bpickle\.loads?\s*\(|\byaml\.load\s*\(/,'Use JSON with schema validation or yaml.safe_load. Never unpickle untrusted data.'),
 r('DTG007','Weak digest for security review','medium','CWE-327',['py','js','mjs','ts'],/\bhashlib\.(?:md5|sha1)\s*\(|createHash\s*\(\s*["'](?:md5|sha1)["']/,'Review purpose. For passwords use Argon2id/scrypt; for integrity use SHA-256 or stronger. Non-security checksums may be acceptable.','low'),
 r('DTG008','Development debugger enabled','high','CWE-489',['py','js','mjs','ts','json'],/\bdebug\s*[:=]\s*(?:True|true)/,'Disable interactive debugging in production. Keep error details in access-controlled logs.'),
 r('DTG009','Literal credential assignment','high','CWE-798',['py','js','mjs','ts','json','yaml','yml','env'],/\b(?:password|api_key|apiKey|secret_key|access_token)\s*[=:]\s*["'][^"'\n]{8,}["']/,'Remove the literal, rotate any real exposed credential, and load it from a secret manager. Reports omit source values.'),
 r('DTG010','Private key material','critical','CWE-321',['*'],/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,'Remove and rotate this key; investigate its history and affected access.','high'),
 r('DTG011','GitHub credential pattern','critical','CWE-798',['*'],/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/,'Revoke the credential, investigate usage, and remove it from current code and history.','high'),
 r('DTG012','Unsafe C string or formatting API','high','CWE-120',['c','h','cpp','hpp','cc'],/\b(?:gets|strcpy|strcat|sprintf)\s*\(/,'Use bounds-aware APIs and explicit lengths; test boundary conditions with sanitizers.'),
 r('DTG013','Workflow has broad write permission','high','CWE-269',['yml','yaml'],/\bpermissions\s*:\s*write-all/,'Set contents: read by default; grant only the required job-scoped permissions.','high'),
 r('DTG014','Workflow executes expression in script','high','CWE-78',['yml','yaml'],/\$\{\{\s*github\.event\.(?:issue|pull_request|comment|discussion)[^}]*\}\}/,'For shell scripts, pass untrusted event text through an environment variable and quote it. Review context: expressions in metadata are not executable.','low'),
 r('DTG015','Workflow action is not pinned to a commit','medium','CWE-829',['yml','yaml'],/^\s*-?\s*uses:\s*(?!\.\/|docker:\/\/)[\w.-]+\/[\w./-]+@(?![a-f0-9]{40}(?:\s|$))[^\s#]+/,'Pin third-party actions to an audited full commit SHA and use Dependabot to review updates.'),
 r('DTG016','Remote script piped to shell','high','CWE-829',['sh','bash','yml','yaml','dockerfile'],/\b(?:curl|wget)\b[^\n]*\|\s*(?:sudo\s+)?(?:bash|sh)\b/,'Fetch a pinned artifact and verify its signature or checksum before execution.'),
 r('DTG017','Wildcard CORS configuration','medium','CWE-942',['py','js','mjs','ts','json'],/Access-Control-Allow-Origin["']?\s*[:=]\s*["']\*|allow_origins\s*=\s*\[\s*["']\*["']/,'Restrict origins for private APIs; review credential handling. Public non-credentialed APIs may intentionally use wildcard CORS.','low'),
 r('DTG018','Disabled container isolation','high','CWE-250',['yml','yaml','sh','bash'],/\bprivileged\s*:\s*true|--privileged\b|\/var\/run\/docker\.sock/,'Avoid privileged mode and Docker socket mounts. Use rootless containers and scoped capabilities.'),
 r('DTG019','Mutable container image tag','medium','CWE-829',['dockerfile'],/^\s*FROM\s+(?!scratch(?:\s|$))[^\s@]+(?<!@sha256:[a-f0-9]{64})(?:\s|$)/i,'Pin the base image by sha256 digest, review updates and scan image dependencies.','low')
];
export function extension(path) {
 const base=path.replaceAll('\\','/').split('/').pop().toLowerCase();
 if(base==='dockerfile'||base.startsWith('dockerfile.')) return 'dockerfile';
 if(base==='.env'||base.startsWith('.env.')) return 'env';
 return base.includes('.')?base.split('.').pop():'';
}
export function scanText(text,path='input.js') {
 const ext=extension(path), findings=[];
 const applicable=rules.filter(rule=>rule.extensions.includes(ext)||rule.extensions.includes('*'));
 text.split(/\r?\n/).forEach((line,index)=>{
  const trimmed=line.trim();
  if(trimmed.startsWith('//')||trimmed.startsWith('#')||trimmed.startsWith('*')) return;
  for(const rule of applicable) {
   const match=rule.pattern.exec(line);
   if(match) findings.push({ruleId:rule.id,title:rule.title,severity:rule.severity,confidence:rule.confidence,cwe:rule.cwe,path,line:index+1,column:match.index+1,fix:rule.fix});
  }
 });
 return findings;
}
export function toSarif(findings) {
 const ids=new Set(findings.map(f=>f.ruleId));
 return {$schema:'https://json.schemastore.org/sarif-2.1.0.json',version:'2.1.0',runs:[{tool:{driver:{name:'DevThreat Guard',version:VERSION,informationUri:'https://github.com/brunnojob/devthreat-guard',rules:rules.filter(r=>ids.has(r.id)).map(r=>({id:r.id,shortDescription:{text:r.title},help:{text:r.fix},properties:{tags:['security',r.cwe]}}))}},results:findings.map(f=>({ruleId:f.ruleId,level:f.severity==='medium'?'warning':'error',message:{text:f.title+'. '+f.fix},locations:[{physicalLocation:{artifactLocation:{uri:f.path.split('/').map(encodeURIComponent).join('/')},region:{startLine:f.line,startColumn:f.column}}}],properties:{severity:f.severity,confidence:f.confidence,cwe:f.cwe}}))}]};
}
