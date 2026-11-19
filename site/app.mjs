import {scanText,toSarif,rules,extension} from './src/engine.mjs';
import {before,after,simpleBefore,simpleAfter} from './fixtures.mjs';
import {lessons,tools,sources} from './content.mjs';
const $=id=>document.getElementById(id);
const dict={labNav:['Laboratório','Lab'],learnNav:['Aprender','Learn'],toolsNav:['Ferramentas','Toolkit'],hero:['Encontre o risco.\nEntenda a causa.\nCorrija com evidência.','Find the risk.\nUnderstand the cause.\nFix with evidence.'],intro:['Segurança que cabe no seu fluxo de desenvolvimento. Analise código no navegador, aprenda a corrigir falhas e leve as verificações para o CI.','Security that fits your development workflow. Review code in your browser, learn to fix weaknesses and bring the checks to CI.'],openLab:['Abrir laboratório ↗','Open the lab ↗'],addCI:['Adicionar ao CI','Add to CI'],privacy:['● Seu código fica no navegador. Sem conta. Sem telemetria.','● Your code stays in your browser. No account. No telemetry.'],rules:['regras explicáveis','explainable rules'],uploads:['uploads de código','code uploads'],reports:['JSON · Markdown · CI','JSON · Markdown · CI'],access:['estudo acessível','accessible learning'],labTitle:['Da falha à correção.','From weakness to fix.'],labDesc:['Os mesmos exemplos. O mesmo motor. Resultados reproduzíveis, sem executar o código analisado.','The same examples. The same engine. Reproducible findings without executing scanned code.'],fileLabel:['Arquivo','File'],before:['Antes / vulnerável','Before / vulnerable'],after:['Depois / corrigido','After / fixed'],codeLabel:['Código para análise','Code to scan'],scan:['Analisar código →','Scan code →'],import:['Importar arquivo','Import file'],results:['Relatório','Report'],filter:['Severidade','Severity'],all:['Todas','All'],limit:['Zero achados significa que estas regras não encontraram padrões no arquivo. Não comprova ausência de vulnerabilidades. Análise heurística sem AST, fluxo de dados, CVEs ou proteção em execução; comentários e strings podem gerar falsos positivos ou negativos.','Zero findings means these rules found no matching patterns in this file. It does not prove absence of vulnerabilities. Heuristic checks without AST, data flow, CVEs or runtime protection; comments and strings may cause false positives or negatives.'],evidence:['Ver evidência da demonstração e escopo','See demo evidence and scope'],evidenceDesc:['Antes: 5 achados no exemplo JavaScript. Depois: 0 após revisão e correções manuais. A ferramenta detecta e orienta; não aplica correções automaticamente. Os testes verificam parâmetros SQL, rejeição de IDs inválidos e uso de textContent. Fixtures vulneráveis são texto inerte, nunca executado.','Before: 5 findings in the JavaScript fixture. After: 0 following review and manual fixes. The tool detects and guides; it does not apply fixes automatically. Tests verify SQL parameters, invalid-ID rejection and textContent use. Vulnerable fixtures are inert text, never executed.'],evidenceLink:['Abrir relatório reproduzível ↗','Open reproducible report ↗'],academyTitle:['Entenda como se defender.','Understand how to defend.'],academyDesc:['Seis módulos curtos. Conceito, ação prática e uma pergunta para verificar o entendimento.','Six short modules. A concept, a practical task and a comprehension question.'],reset:['Reiniciar progresso','Reset progress'],toolsTitle:['Veja o que um atacante vê.','See what an attacker sees.'],toolsDesc:['Conheça ferramentas de teste e investigação, suas limitações e a defesa correspondente. O site não faz varredura de redes ou alvos.','Understand testing and investigation tools, their limits and corresponding defenses. This site does not scan networks or targets.'],ciTitle:['Encontre falhas antes do merge.','Catch weaknesses before merge.'],ciDesc:['Use a Action com acesso somente de leitura. Bloqueie achados altos, exporte SARIF e revise cada resultado.','Run the read-only action. Gate high-severity findings, export SARIF and review every result.'],pin:['Em produção, fixe também DevThreat Guard por um commit SHA auditado. A Action usa o Node 24 do runner e não instala dependências.','In production, pin DevThreat Guard to an audited commit SHA too. The action uses the runner Node 24 and installs no dependencies.'],sourcesTitle:['Fontes, decisões e limites.','Sources, decisions and limits.'],sourcesDesc:['Referências consultadas em 19/11/2026. Estudos orientam prioridades; não validam a eficácia deste produto.','Sources reviewed on 2026-11-19. Research informs priorities; it does not validate product effectiveness.'],footer:['Feito por brunnojob para a comunidade dev. MIT · Revisão humana faz parte da defesa.','Built by brunnojob for the developer community. MIT · Human review is part of the defense.']};
Object.assign(dict,{
 chooseFile:['Escolher arquivo','Choose file'],custom:['Exemplo personalizado','Custom example'],
 compareTitle:['O mesmo código. Uma revisão orientada.','The same code. A guided review.'],
 compareIntro:['Exemplo didático: três padrões de risco em uma função curta. A ferramenta analisa o texto; você revisa e corrige.','Teaching example: three risky patterns in a short function. The tool analyzes text; you review and fix it.'],
 withoutTitle:['Sem a ferramenta: revisão manual','Without the tool: manual review'],
 withoutDesc:['Você recebe o código e precisa localizar execução dinâmica, SQL interpolado e HTML não confiável. Nenhum alerta foi gerado neste painel.','You receive the code and must identify dynamic execution, interpolated SQL and untrusted HTML. No alerts are generated in this panel.'],
 withTitle:['Com a ferramenta: pontos para investigar','With the tool: review guidance'],
 withDesc:['O motor encontra padrões e explica o próximo passo. Um alerta não prova exploração e não substitui revisão humana.','The engine flags patterns and explains the next step. A finding does not prove exploitability or replace human review.'],
 manualFix:['Depois da correção manual','After manual remediation'],
 loadSimple:['Analisar este exemplo ↑','Analyze this example ↑'],
 loadFixed:['Analisar a versão corrigida ↑','Analyze the corrected version ↑'],
 compareLimit:['Comparação didática, sem medição de tempo ou de eficácia humana. A ausência de alertas na versão corrigida vale apenas para estas regras e este exemplo.','Teaching comparison, not a measurement of time or human effectiveness. No findings in the corrected version applies only to these checks and this example.']
});
let lang=0,findings=[],scanned=false,completed=[];
try{lang=localStorage.getItem('dtg-lang')==='en'?1:0;const p=JSON.parse(localStorage.getItem('dtg-progress')||'[]');if(Array.isArray(p))completed=p.filter(x=>lessons.some(l=>l.id===x));}catch{}
const tr=(pt,en)=>lang?en:pt;
function node(tag,text,className){const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(className)n.className=className;return n;}
function save(){try{localStorage.setItem('dtg-progress',JSON.stringify(completed));localStorage.setItem('dtg-lang',lang?'en':'pt');}catch{}}
function renderResults(){
 const box=$('findings');box.replaceChildren();$('status').textContent=scanned?tr(`${findings.length} achados`,`${findings.length} findings`):tr('Análise pendente','Scan pending');
 if(!scanned){box.append(node('p',tr('Código alterado. Execute a análise.','Code changed. Run the scan.'),'empty'));return;}
 const filtered=findings.filter(f=>$('severity').value==='all'||f.severity===$('severity').value);
 if(!findings.length){const n=node('div',undefined,'empty');n.append(node('strong',tr('0 achados neste arquivo','0 findings in this file')),node('p',tr('Revise o escopo e valide a correção com testes.','Review coverage and validate the fix with tests.')));box.append(n);}
 else if(!filtered.length)box.append(node('p',tr('Nenhum achado neste filtro.','No findings for this filter.')));
 for(const f of filtered){const item=node('article',undefined,'finding');item.append(node('span',f.severity.toUpperCase(),'tag'),node('span',`${f.ruleId} / ${f.cwe}`,'tag'),node('h3',f.title),node('p',`${f.path}:${f.line}:${f.column} · ${tr('confiança','confidence')}: ${f.confidence}`),node('p',f.fix));box.append(item);}
}
function scan(){const path=$('filename').value||'input.js',source=$('code').value;if(source.length>524288){$('status').textContent=tr('Limite: 512 KiB','Limit: 512 KiB');return;}
 const ext=extension(path);if(!rules.some(r=>r.extensions.includes(ext))){findings=[];scanned=false;renderResults();$('status').textContent=tr('Tipo sem regras específicas; use a CLI para cobertura.','No type-specific rules; use CLI coverage.');return;}
 findings=scanText(source,path);scanned=true;renderResults();}
function render(){document.documentElement.lang=lang?'en':'pt-BR';$('language').textContent=lang?'PT':'EN';for(const el of document.querySelectorAll('[data-i]')){const value=dict[el.dataset.i]?.[lang];if(value===undefined)continue;if(el.dataset.i==='hero'){el.replaceChildren();value.split('\n').forEach((s,i)=>{if(i)el.append(document.createElement('br'));el.append(node(i===2?'em':'span',s));});}else el.textContent=value;}
 renderFileName();renderComparison();
 $('lessons').replaceChildren();$('tools').replaceChildren();$('sources').replaceChildren();
 $('progress').textContent=tr(`${completed.length} / 6 módulos concluídos · salvo apenas neste navegador`,`${completed.length} / 6 modules completed · saved only in this browser`);
 for(const lesson of lessons){const card=node('article',undefined,'card');card.append(node('h3',lesson.title[lang]),node('p',lesson.body[lang]),node('p',lesson.task[lang],'task'));const fs=node('fieldset');fs.append(node('legend',lesson.q[lang]));const feedback=node('div',completed.includes(lesson.id)?tr('✓ Concluído','✓ Completed'):'','quiz-result');feedback.setAttribute('role','status');lesson.answers.forEach((a,i)=>{const b=node('button',a[lang]);if(completed.includes(lesson.id)&&i===lesson.correct)b.className='correct';b.addEventListener('click',()=>{if(i===lesson.correct){if(!completed.includes(lesson.id))completed.push(lesson.id);save();render();}else feedback.textContent=tr('Revise o conceito e tente novamente.','Review the concept and try again.');});fs.append(b);});card.append(fs,feedback);$('lessons').append(card);}
 for(const [name,url,desc]of tools){const c=node('article',undefined,'card');c.append(node('h3',name),node('p',desc[lang]));const a=node('a',tr('Documentação oficial ↗','Official documentation ↗'));a.href=url;c.append(a);$('tools').append(c);}
 for(const [name,url,date,desc]of sources){const c=node('article',undefined,'source');const a=node('a',name+' ↗');a.href=url;c.append(node('small',date),node('br'),a,node('p',desc[lang]));$('sources').append(c);}
 renderResults();}
function invalidate(){$('sample').value='custom';scanned=false;$('export').disabled=true;$('sarif').disabled=true;renderResults();}
$('scan').addEventListener('click',()=>{scan();$('export').disabled=!scanned;$('sarif').disabled=!scanned;});
$('sample').addEventListener('change',()=>{$('code').value=$('sample').value==='before'?before:after;$('filename').value=$('sample').value+'.js';scan();$('export').disabled=false;$('sarif').disabled=false;});
$('code').addEventListener('input',invalidate);$('filename').addEventListener('input',invalidate);$('severity').addEventListener('change',renderResults);
$('language').addEventListener('click',()=>{lang=1-lang;save();render();});$('reset').addEventListener('click',()=>{completed=[];save();render();});
$('choose-file').addEventListener('click',()=>$('file').click());
$('file').addEventListener('change',async()=>{const f=$('file').files[0];if(!f)return;if(f.size>524288){$('status').textContent=tr('Limite: 512 KiB','Limit: 512 KiB');return;}try{$('code').value=await f.text();$('filename').value=f.name;renderFileName();invalidate();}catch{$('status').textContent=tr('Não foi possível ler o arquivo','Could not read file');}});
function download(format){if(!scanned)return;const report=format==='sarif'?toSarif(findings):{tool:'DevThreat Guard',scope:dict.limit[lang],findings};const blob=new Blob([JSON.stringify(report,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='devthreat-report.'+(format==='sarif'?'sarif':'json');a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
$('export').addEventListener('click',()=>download('json'));$('sarif').addEventListener('click',()=>download('sarif'));
$('code').value=before;$('filename').value='before.js';scan();render();

function renderFileName(){
 const selected=$('file').files[0];
 $('file-name').textContent=selected?selected.name:tr('Nenhum arquivo selecionado','No file selected');
 $('file').setAttribute('aria-label',dict.chooseFile[lang]);
}
function renderComparison(){
 $('simple-source').textContent=simpleBefore;
 $('simple-fixed').textContent=simpleAfter;
 const found=scanText(simpleBefore,'simple-before.js');
 $('simple-findings').replaceChildren();
 const explanations={DTG001:['eval transforma dados em código. Use um parser JSON.','eval turns data into code. Use a JSON parser.'],DTG004:['Passe o ID como parâmetro separado da consulta SQL.','Pass the ID separately as a bound SQL parameter.'],DTG002:['Renderize o nome com textContent, sem interpretar HTML.','Render the name with textContent without interpreting HTML.']};
 for(const f of found)$('simple-findings').append(node('li',`${f.ruleId} · ${tr('linha','line')} ${f.line}: ${explanations[f.ruleId]?.[lang]??f.fix}`));
 const remaining=scanText(simpleAfter,'simple-after.js').length;
 $('simple-summary').textContent=tr(`${found.length} alertas antes → ${remaining} após correção manual (somente este exemplo).`,`${found.length} findings before → ${remaining} after manual remediation (this example only).`);
}
function loadSimple(fixed){
 $('code').value=fixed?simpleAfter:simpleBefore;$('filename').value=fixed?'simple-after.js':'simple-before.js';
 // No existing sample corresponds to this source. Show an explicit custom selection.
 $('sample').value='custom';scan();$('export').disabled=!scanned;$('sarif').disabled=!scanned;
 $('code').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'instant':'smooth',block:'center'});
}
$('load-simple').addEventListener('click',()=>loadSimple(false));
$('load-fixed').addEventListener('click',()=>loadSimple(true));
