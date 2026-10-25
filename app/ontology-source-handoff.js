/* Optional source-intent handoff. No source fetch, writer, grant or adoption. */
(function(global){
  'use strict';
  const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
  const text=(x,n)=>typeof x==='string'&&x.trim()&&x.length<=n;
  const node=(tag,value)=>{const result=document.createElement(tag);if(value!==undefined)result.textContent=value;return result;};
  function mount(host,settings){
    if(!object(settings)||Object.keys(settings).sort().join(',')!=='format,layer,ontologySha256'||settings.format!=='ontology-source-handoff-settings/v1'||!text(settings.layer,64)||!/^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/.test(settings.layer)||!/^[a-f0-9]{64}$/.test(settings.ontologySha256))throw Error('Explicit source layer and Registry basis required');
    host.replaceChildren();
    host.append(node('h2','Propose a Registry source change'),node('p','Ordinary glossary and Term records use their declared content writer. This separate handoff is for versioned Registry definitions, aliases, payload schemas and relations.'),node('p','Selected source layer: '+settings.layer+' · Registry basis: '+settings.ontologySha256));
    const form=node('form'),status=node('p'),preview=node('pre'),download=node('button','Download source intent');download.type='button';download.disabled=true;status.setAttribute('role','status');
    const values={};
    for(const [name,label,type] of [['revision','Next minor or major source revision','input'],['changes','Typed additive changes (JSON array)','textarea'],['reason','Reason for source review','textarea'],['evidence','Evidence claim references (one per line)','textarea']]){
      const wrap=node('label',label),input=node(type);input.name=name;input.dataset.ontologySource=name;input.maxLength=name==='changes'?98304:name==='reason'?2000:65536;
      if(type==='textarea')input.rows=name==='changes'?10:3;
      wrap.append(input);form.append(wrap);values[name]=input;
    }
    values.changes.value='[]';
    form.append(node('p','Supported operations: add-term, add-aliases for a term owned by this physical layer, add-kind with a real payloadSchema and declared idConvention, add-edge with explicit existing/new kind domain and range. Removal, identity changes and meaning changes require the full upgrade workflow.'));
    const prepare=node('button','Prepare operator handoff');prepare.type='submit';form.append(prepare,download);host.append(form,status,preview);
    let artifact=null;
    const clear=()=>{artifact=null;download.disabled=true;preview.textContent='';status.textContent='Recheck the source intent after editing. No source was written.';};
    for(const input of Object.values(values))input.addEventListener('input',clear);
    form.addEventListener('submit',event=>{
      event.preventDefault();clear();
      try{
        if(!/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.test(values.revision.value)||!text(values.reason.value,2000))throw Error('Revision and reason required');
        const changes=JSON.parse(values.changes.value),evidence=values.evidence.value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
        if(!Array.isArray(changes)||!changes.length||changes.length>64||!changes.every(x=>object(x)&&['add-term','add-aliases','add-kind','add-edge'].includes(x.op))||!evidence.length||evidence.length>32||!evidence.every(x=>text(x,2000)))throw Error('Bounded typed changes and evidence required');
        // Preserve the original JSON value tokens, including schema integer
        // bounds beyond 2^53. Parsed values are used only for shallow UI checks.
        const wire='{\n  "format":"ontology-source-intent/v1",\n  "expectedOntologySha256":'+JSON.stringify(settings.ontologySha256)+',\n  "changes":'+values.changes.value.trim()+',\n  "reason":'+JSON.stringify(values.reason.value)+',\n  "evidence":'+JSON.stringify(evidence)+'\n}\n';
        if(new TextEncoder().encode(wire).byteLength>131072)throw Error('Intent exceeds bound');
        artifact={wire,revision:values.revision.value};download.disabled=false;
        preview.textContent=wire;
        status.textContent='Intent only. An authorized source operator must run scripts/ontology-source-proposal.py with this intent, the actual source root, layer '+settings.layer+' and next revision '+artifact.revision+'. That command rechecks current source and canonical Registry validity, then produces a private patch for normal source review. This panel grants nothing and writes no source.';
      }catch{status.textContent='Source intent unavailable. Check the typed changes, revision, reason and evidence. No source was written.';}
    });
    download.addEventListener('click',()=>{
      if(!artifact)return;const url=URL.createObjectURL(new Blob([artifact.wire],{type:'application/json'})),link=node('a');link.href=url;link.download='ontology-source-intent.json';link.click();setTimeout(()=>URL.revokeObjectURL(url),0);
    });
    return {clear,destroy(){clear();host.replaceChildren();}};
  }
  global.KBOntologySourceHandoff={mount};
})(typeof window!=='undefined'?window:globalThis);
