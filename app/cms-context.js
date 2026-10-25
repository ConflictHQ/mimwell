/* Optional CMS context: existing governed navigation, explicit writer hints,
 * and owner-reviewed published recipe guidance. No new endpoint or write tool. */
(function(global){
  'use strict';
  const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x),text=(x,n)=>typeof x==='string'&&x.trim()&&x.length<=n;
  const digest=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x),encoder=new TextEncoder();
  const element=(name,value)=>{const e=document.createElement(name);if(value!==undefined)e.textContent=value;return e;};
  async function sha(bytes){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',bytes))].map(x=>x.toString(16).padStart(2,'0')).join('');}
  function validateSettings(settings){
    if(!object(settings)||Object.keys(settings).sort().join(',')!=='navigation,owners,protocolVersion'||settings.protocolVersion!=='1.0'||!object(settings.navigation)||!Array.isArray(settings.owners)||settings.owners.length>64)throw Error('Invalid CMS context selection');
    const seen=new Set();
    for(const row of settings.owners){
      if(!object(row)||Object.keys(row).sort().join(',')!=='binding,guidance,manifestSha256,operationsAuthority,participant,realm,realmAuthority,realmRevision'||!text(row.participant,200)||!digest(row.manifestSha256)||!text(row.realm,200)||!text(row.realmAuthority,2000)||!text(row.realmRevision,2000)||!text(row.operationsAuthority,2000)||!digest(row.binding))throw Error('Invalid explicit owning-writer hint');
      const key=JSON.stringify([row.participant,row.realm]);if(seen.has(key))throw Error('Ambiguous owning-writer hint');seen.add(key);
      if(row.guidance!==null&&(!object(row.guidance)||Object.keys(row.guidance).sort().join(',')!=='path,sha256'||!text(row.guidance.path,512)||!/^\/app\/[A-Za-z0-9_-]+\.json$/.test(row.guidance.path)||!digest(row.guidance.sha256)))throw Error('Only an explicitly pinned published guidance artifact may be selected');
    }
    return settings;
  }
  function matches(observation,settings){
    const p=observation?.participant;if(!p||!text(observation.authorization?.principal,2000)||!Array.isArray(p.realms)||!digest(p.manifest?.sha256))return [];
    return settings.owners.filter(row=>row.participant===p.id&&row.manifestSha256===p.manifest.sha256&&p.realms.some(realm=>realm.realm===row.realm&&realm.authority===row.realmAuthority&&realm.revision===row.realmRevision));
  }
  function validateGuidance(value){
    if(!object(value)||value.format!=='cms-recipe-guidance/v1'||!digest(value.basisSha256)||!object(value.recipe)||!text(value.recipe.id,2000)||!text(value.recipe.version,100)||!Array.isArray(value.tasks)||!value.tasks.length||value.tasks.length>32||!Array.isArray(value.fieldHints)||value.fieldHints.length>1024||value.authorization!=='not-evaluated'||value.mutationsPerformed!==false||value.publication!=='candidate-requires-explicit-owner-review')throw Error('Invalid published recipe guidance');
    const ids=new Set();
    for(const task of value.tasks){
      if(!object(task)||!text(task.id,200)||ids.has(task.id)||!Array.isArray(task.tools)||task.tools.length>64||!Array.isArray(task.inputs)||!Array.isArray(task.outputs))throw Error('Invalid declared skill');ids.add(task.id);
      for(const key of ['purpose','success','failure','example','counterexample','prompt','toolTemplate'])if(!text(task[key],65536))throw Error('Invalid declared instruction');
      for(const tool of task.tools)if(!object(tool)||!object(tool.capability)||!text(tool.capability.id,2000)||!text(tool.capability.version,100)||tool.authorization!=='not-evaluated'||typeof tool.localImplementationObserved!=='boolean'||tool.component!==null&&(!object(tool.component)||!text(tool.component.id,2000)||!text(tool.component.version,100)||!digest(tool.component.sha256)))throw Error('Invalid selected component declaration');
    }
    for(const row of value.fieldHints)if(!object(row)||!text(row.schema,512)||!digest(row.schemaSha256)||!text(row.schemaPointer,2000)||!object(row.hint))throw Error('Invalid declared field hint');
    return value;
  }
  async function readGuidance(reference,signal){
    const response=await fetch(reference.path,{credentials:'same-origin',cache:'no-store',redirect:'error',signal});
    if(!response.ok||!response.body||!(response.headers.get('content-type')||'').toLowerCase().startsWith('application/json'))throw Error('Published guidance unavailable');
    const reader=response.body.getReader(),parts=[];let count=0,done=false;
    try{for(;;){const item=await reader.read();if(item.done){done=true;break;}count+=item.value.byteLength;if(count>1048576)throw Error('Guidance exceeds publication bound');parts.push(item.value);}}
    finally{if(!done)await reader.cancel().catch(()=>{});reader.releaseLock();}
    const bytes=new Uint8Array(count);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
    if(signal.aborted||await sha(bytes)!==reference.sha256)throw Error('Guidance publication changed');
    return validateGuidance(JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes)));
  }
  function mount(host,settings,writer){
    settings=validateSettings(settings);if(!writer||typeof writer.selectAuthority!=='function'||typeof writer.suspendOwner!=='function'||!global.KBFederationNavigation)throw Error('Existing CMS/navigation components required');
    host.replaceChildren();const navigation=element('section'),selection=element('section'),guidance=element('section'),status=element('p');status.setAttribute('role','status');
    navigation.setAttribute('aria-label','Owning brain navigation');selection.setAttribute('aria-label','Explicit owning-writer selection');guidance.setAttribute('aria-label','Selected component skill and field guidance');
    host.append(element('h2','Choose the owning brain'),element('p','Navigation does not grant record access or change the connected writer. Select its explicitly configured writer, then use freshly verified workbench actions.'),navigation,selection,guidance,status);
    let generation=0,controller=null,current=null;
    function clear(){++generation;if(controller)controller.abort();controller=null;current=null;selection.replaceChildren();guidance.replaceChildren();writer.suspendOwner();status.textContent='Choose a visible brain. Existing uncertain proposals remain in their original writer until reconciled.';}
    function renderGuidance(report){
      guidance.replaceChildren(element('h3','Recipe '+report.recipe.id+'@'+report.recipe.version),element('p','Pinned declaration guidance. This does not install components, change configuration, grant access or execute skills.'));
      const selected=new Set();
      for(const task of report.tasks){
        const section=element('section'),label=element('label'),toggle=element('input');toggle.type='checkbox';toggle.dataset.cmsTask=task.id;label.append(toggle,document.createTextNode(task.purpose));section.append(label);
        const details=element('details');details.append(element('summary','Declared skill, components and hints'),element('p','Success: '+task.success),element('p','Refuse/unknown: '+task.failure),element('pre',task.prompt),element('pre',task.toolTemplate));
        for(const tool of task.tools)details.append(element('p',tool.capability.id+'@'+tool.capability.version+' · '+(tool.component?tool.component.id+'@'+tool.component.version:'No compatible selected component')+' · local implementation observed: '+tool.localImplementationObserved+' · permission not evaluated'));
        toggle.onchange=()=>{toggle.checked?selected.add(task.id):selected.delete(task.id);draft.textContent=JSON.stringify({format:'cms-guidance-composition-draft/v1',basisSha256:report.basisSha256,recipe:report.recipe,tasks:[...selected],executionAuthorized:false,configurationApplied:false},null,2);};section.append(details);guidance.append(section);
      }
      for(const hint of report.fieldHints){
        const details=element('details');details.append(element('summary',hint.schema+' '+hint.schemaPointer),element('pre',JSON.stringify(hint.hint,null,2)));guidance.append(details);
      }
      const draft=element('pre','Select declared skills to compose a draft for the existing operator recipe/config review. Content changes continue through their canonical writer.');draft.dataset.cmsComposition='';guidance.append(draft);
    }
    function selected(observation){
      clear();const candidates=matches(observation,settings);if(!candidates.length){status.textContent='No exact current writer hint is declared for this visible source. Do not infer one from names, folders or URLs.';return;}
      current=observation;const currentGeneration=generation;
      for(const row of candidates){const button=element('button','Use registered writer '+row.operationsAuthority);button.type='button';button.dataset.cmsOwner=row.operationsAuthority;
        button.onclick=()=>{if(generation!==currentGeneration||current!==observation)return;const accepted=writer.selectAuthority(row.operationsAuthority,row.binding,observation.authorization.principal);status.textContent=accepted?'Writer selection requested. Permission and binding are checked by its authenticated operation; navigation grants nothing.':'Finish or reconcile the active/uncertain proposal before switching owning writers.';};selection.append(button);
        if(row.guidance){const show=element('button','Load reviewed guidance for '+row.operationsAuthority);show.type='button';show.onclick=async()=>{if(controller)controller.abort();controller=new AbortController();const active=controller;const timer=setTimeout(()=>active.abort(),12000);guidance.replaceChildren();try{const report=await readGuidance(row.guidance,active.signal);if(generation!==currentGeneration||active.signal.aborted)return;renderGuidance(report);}catch{if(generation===currentGeneration)guidance.replaceChildren(element('p','Guidance unavailable or changed; no unpinned/private report fallback.'));}finally{clearTimeout(timer);}};selection.append(show);}
      }
    }
    const nav=global.KBFederationNavigation.mount(navigation,settings.navigation,{selection:selected,clear});
    const hidden=()=>{if(document.hidden){clear();nav?.clear();}};document.addEventListener('visibilitychange',hidden);global.addEventListener('pagehide',clear);
    return {clear, destroy(){clear();nav?.destroy();document.removeEventListener('visibilitychange',hidden);global.removeEventListener('pagehide',clear);host.replaceChildren();}};
  }
  global.KBCMSContext={mount,validateSettings,matches,validateGuidance};
})(typeof window!=='undefined'?window:globalThis);
