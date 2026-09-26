/* Exact context inspection. No model calls, source mutations or browser credentials. */
(function(global) {
  'use strict';
  const ceiling = 4194304;
  const defaults = {maxNodes:100,maxEdges:200,maxHops:4,maxReferences:20,maxQuestions:20,maxBytes:262144};
  const limits = {maxNodes:1000,maxEdges:2000,maxHops:8,maxReferences:20,maxQuestions:100,maxBytes:1048576};
  const node = (tag,text) => {const el=document.createElement(tag);if(text!=null)el.textContent=text;return el;};
  const canonical = value => Array.isArray(value)?'['+value.map(canonical).join(',')+']':
    value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
  async function validate(report) {
    const captured=report&&report.context, summary=report&&report.summary;
    if(report?.format!=='context-inspection/v1'||captured?.encoding!=='utf-8'||captured?.mediaType!=='application/json'||
      typeof captured.payload!=='string'||!/^[a-f0-9]{64}$/.test(captured.sha256)||!summary)throw Error('Invalid inspection');
    const bytes=new TextEncoder().encode(captured.payload);
    if(bytes.length!==captured.bytes||bytes.length>1048576)throw Error('Invalid payload length');
    const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
    const payload=JSON.parse(captured.payload);
    if(digest!==captured.sha256||summary.contextSha256!==digest||payload.protocolVersion!=='1.0'||
      !['nodes','edges','references','gaps','truncation'].every(key=>Array.isArray(payload[key]))||
      canonical(summary.basis)!==canonical(payload.request)||canonical(summary.authorization)!==canonical(payload.authorization)||
      canonical(summary.gaps)!==canonical(payload.gaps)||canonical(summary.coverage)!==canonical(payload.coverage)||
      canonical(summary.truncation)!==canonical(payload.truncation)||
      canonical(summary.conflicts)!==canonical(payload.gaps.filter(g=>g.state==='contradiction'))||
      !summary.freshness||!['current','stale','unknown'].includes(summary.freshness.state))throw Error('Mismatched inspection');
    if(payload.projectionFreshness&&canonical(summary.freshness)!==canonical(payload.projectionFreshness))throw Error('Mismatched freshness');
    if(!payload.projectionFreshness&&summary.freshness.state!=='unknown')throw Error('Missing freshness observation');
    return {payload,summary,captured};
  }
  function mount(host,options={}) {
    host.replaceChildren();
    let basis=null, sequence=0, controller, payloadText=null, downloadUrl=null;
    const form=node('form'), refresh=node('button','Refresh source basis'), preview=node('button','Preview context');
    if(options.operation==='review')preview.textContent='Review selected context';
    refresh.type='button';preview.type='submit';preview.disabled=true;
    const type=node('select');type.id='ci-target-type';type.append(new Option('Task','task'),new Option('Subject and question','subject'));
    const target=node('input');target.id='ci-target';target.required=true;target.maxLength=1000;
    const question=node('input');question.id='ci-question';question.maxLength=2000;question.disabled=true;
    const labelled=(text,input)=>{const label=node('label',text);label.htmlFor=input.id;const wrap=node('div');wrap.append(label,input);return wrap;};
    form.append(labelled('Context type',type),labelled('Record ID',target),labelled('Question',question));
    const budget=node('details'), title=node('summary','Context limits');budget.append(title);
    const fields={};
    for(const [key,value] of Object.entries(defaults)) {
      const input=node('input');input.type='number';input.id='ci-'+key;input.min=['maxNodes','maxBytes'].includes(key)?'1':'0';input.max=String(limits[key]);input.step='1';input.value=String(value);input.required=true;
      fields[key]=input;budget.append(labelled(key.replace('max','Maximum ').replace(/([A-Z])/g,' $1').trim(),input));
    }
    const toolbar=node('div');toolbar.className='ci-toolbar';toolbar.append(refresh,preview);form.append(budget,toolbar);
    const status=node('p','Loading source basis…');status.setAttribute('role','status');
    const basisText=node('p');basisText.className='ci-coordinate';
    const content=node('section');content.setAttribute('aria-label','Context inspection');content.tabIndex=-1;
    host.append(form,status,basisText,content);
    function clear() {
      payloadText=null;content.replaceChildren();
      if(downloadUrl)URL.revokeObjectURL(downloadUrl);downloadUrl=null;
    }
    function invalidate(message) {
      ++sequence;if(controller)controller.abort();clear();host.removeAttribute('aria-busy');status.textContent=message;
    }
    async function post(operation,body,signal) {
      const response=await fetch('/brain-context/'+operation,{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',signal,
        headers:{'content-type':'application/json'},body:JSON.stringify(body)});
      if(!response.ok||!response.body||!(response.headers.get('content-type')||'').toLowerCase().startsWith('application/json'))throw Error('Unavailable');
      const reader=response.body.getReader(),parts=[];let size=0;
      try {
        for(;;){const item=await reader.read();if(item.done)break;size+=item.value.byteLength;if(size>ceiling)throw Error('Too large');parts.push(item.value);}
      }catch(error){await reader.cancel().catch(()=>{});throw error;}finally{reader.releaseLock();}
      const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    }
    function section(title,value) {
      const details=node('details'), heading=node('summary',title), pre=node('pre',typeof value==='string'?value:JSON.stringify(value,null,2));
      details.append(heading,pre);content.append(details);
    }
    function render(checked) {
      const {payload,summary,captured}=checked;
      payloadText=captured.payload;
      content.append(node('h2','Captured context'),node('p',payload.nodes.length+' records · '+payload.edges.length+' relationships · '+captured.bytes+' bytes'),
        node('p','Freshness: '+summary.freshness.state+' — '+summary.freshness.reason),
        node('p','Coverage: '+summary.coverage.state),node('p','Truncation: '+(payload.truncation.join(', ')||'none reported')),
        node('p',summary.consumption));
      const digest=node('p','SHA-256: '+captured.sha256);digest.className='ci-coordinate';content.append(digest);
      section('Scope, revisions and limits',payload.request);
      if(options.render)options.render(content,checked);
      else section('Evidence and records',{nodes:payload.nodes,edges:payload.edges,references:payload.references});
      section('Gaps ('+payload.gaps.length+')',payload.gaps);
      section('Declared conflicts ('+summary.conflicts.length+')',summary.conflicts);
      content.append(node('p',summary.conflictAssessment));
      section('Question coverage',payload.coverage);
      section('Exact agent payload',captured.payload);
      const download=node('button','Download captured context');download.type='button';
      download.onclick=()=>{
        if(payloadText===null)return;
        if(downloadUrl)URL.revokeObjectURL(downloadUrl);
        downloadUrl=URL.createObjectURL(new Blob([new TextEncoder().encode(payloadText)],{type:'application/json'}));
        const a=node('a');a.href=downloadUrl;a.download='context-'+captured.sha256.slice(0,12)+'.json';a.click();
      };
      content.append(download);content.focus();
    }
    async function load(operation) {
      invalidate(operation==='basis'?'Loading source basis…':'Compiling the selected context…');
      const current=sequence;controller=new AbortController();const selectedController=controller, signal=selectedController.signal;
      const timeout=setTimeout(()=>selectedController.abort(),12000);host.setAttribute('aria-busy','true');
      try {
        if(operation==='basis') {
          basis=null;preview.disabled=true;basisText.textContent='';
          const result=await post('basis',{},signal);
          if(current!==sequence)return;
          if(signal.aborted||document.hidden)throw Error('Inspection cancelled');
          if(result.protocolVersion!=='1.0'||!Array.isArray(result.scopes)||!result.scopes.length||!result.recipe||!result.revisions||typeof result.asOf!=='string')throw Error('Invalid basis');
          basis=result;basisText.textContent='Scope: '+result.scopes.join(', ')+' · Knowledge basis: '+result.asOf;
          preview.disabled=false;status.textContent='Source basis ready. Choose a record to preview.';
        } else {
          if(!basis)throw Error('No basis');
          const limits=Object.fromEntries(Object.entries(fields).map(([key,input])=>[key,Number(input.value)]));
          const selected={type:type.value,id:target.value.trim()};if(type.value==='subject')selected.question=question.value.trim();
          const query={...basis,target:selected,budget:limits};
          const result=await post(options.operation||'inspect',query,signal), checked=await (options.validate||validate)(result);
          if(current!==sequence)return;
          if(signal.aborted||document.hidden)throw Error('Inspection cancelled');
          if(canonical(checked.payload.request)!==canonical(query))throw Error('Wrong request');
          render(checked);status.textContent='Preview ready. Review evidence and gaps before use.';
        }
      } catch {
        if(current!==sequence)return;
        clear();basis=null;preview.disabled=true;basisText.textContent='';status.textContent='Context unavailable. Refresh the source basis and try again.';
      } finally {clearTimeout(timeout);if(current===sequence)host.removeAttribute('aria-busy');}
    }
    form.addEventListener('input',()=>invalidate('Selection changed. Preview again before use.'));
    type.addEventListener('change',()=>{question.disabled=type.value!=='subject';question.required=!question.disabled;invalidate('Selection changed. Preview again before use.');});
    form.onsubmit=event=>{event.preventDefault();if(form.reportValidity())load('inspect');};
    refresh.onclick=()=>load('basis');
    document.addEventListener('visibilitychange',()=>{
      if(document.hidden){invalidate('Preview cleared while this page was hidden.');basis=null;preview.disabled=true;basisText.textContent='';}
      else load('basis');
    });
    global.addEventListener('pagehide',()=>invalidate('Preview cleared.'));
    load('basis');
  }
  global.KBContextInspection={mount,validate};
  document.addEventListener('DOMContentLoaded',()=>{
    const host=document.querySelector('[data-kb-context-inspection]');if(!host)return;
    Promise.resolve(global.KBShell?global.KBShell.mount({title:'Context inspector'}):null)
      .then(()=>mount(host)).catch(()=>{host.textContent='Context inspector unavailable.';});
  });
})(window);
