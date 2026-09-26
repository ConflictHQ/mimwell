/* Optional composable workbench. The selected host owns identity and writers. */
(function(global) {
  'use strict';
  const ceiling=4194304;
  const node=(tag,text)=>{const el=document.createElement(tag);if(text!=null)el.textContent=text;return el;};
  const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
  const same=(a,b)=>canonical(a)===canonical(b);
  async function validate(report,request) {
    if(!['knowledge-operation-request/v1','knowledge-operation-request/v2','knowledge-operation-request/v3'].includes(request.format)||
      report?.format!==request.format.replace('knowledge-operation-request/','knowledge-operation/')||report.state!=='completed'||
      report.authority!==request.authority||report.operation!==request.operation||
      typeof report.nativeWire!=='string'||!/^[a-f0-9]{64}$/.test(report.nativeSha256)||
      typeof report.requestWire!=='string'||!/^[a-f0-9]{64}$/.test(report.requestSha256)||
      !report.authorization?.principal||!report.authorization.evaluatedAt||!report.authorization.revalidatedAt)
      throw Error('Invalid operation response');
    const raw=new TextEncoder().encode(report.nativeWire);
    if(raw.length>ceiling)throw Error('Native result too large');
    const sha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',raw)),b=>b.toString(16).padStart(2,'0')).join('');
    if(sha!==report.nativeSha256||!same(JSON.parse(report.nativeWire),report.native))throw Error('Native result changed');
    const requestBytes=new TextEncoder().encode(report.requestWire);
    const requestSha=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',requestBytes)),b=>b.toString(16).padStart(2,'0')).join('');
    if(requestSha!==report.requestSha256||!same(JSON.parse(report.requestWire),request))throw Error('Operation request changed');
    return report.native;
  }
  function mount(host,options={}) {
    host.replaceChildren();
    const wires=new WeakMap();
    let sequence=0, controller=null, activeWrite=false, uncertain=false, principal=null, description=null, selectedRecord=null,
      capture=null, extraction=null, sourcePreview=null, proposal=null, publication=null, transfer=null, sourcePage=null, proposalPage=null;
    const inputs={}, buttons=[], outputs=[];
    const status=node('p','Choose the brain you are allowed to change, then connect to begin.');status.setAttribute('role','status');
    const identity=node('p');identity.className='ko-coordinate';
    const settings=node('section');settings.className='ko-connect';
    function field(parent,name,label,{type='text',value=''}={}) {
      const plain={authority:'Brain to change',record:'Record reference',collection:'Type of information',evidence:'Source for this change',reason:'Why this should change',reviewCollection:'Type of suggestion'};
      const wrap=node('label',plain[name]||label),input=node(type==='textarea'?'textarea':type==='select'?'select':'input');
      input.id='ko-'+name;input.name=name;if(input.tagName==='INPUT')input.type=type;
      if(type!=='select'){input.value=value;input.maxLength=type==='textarea'?65536:2000;}
      if(type==='textarea')input.rows=5;
      wrap.htmlFor=input.id;wrap.append(input);parent.append(wrap);inputs[name]=input;return input;
    }
    field(settings,'authority','Authority',{value:options.authority||''});
    function button(parent,name,label,handler,{ready=false}={}) {
      const control=node('button',label);control.type='button';control.dataset.action=name;control.disabled=!ready;
      control.onclick=()=>{if(!controller)handler();};parent.append(control);buttons.push(control);return control;
    }
    const tabs=node('nav');tabs.className='ko-tabs';tabs.setAttribute('aria-label','Knowledge tasks');
    const panels={};
    for(const [key,label] of [['collect','Collect'],['record','Record'],['review','Review'],['publish','Publish'],['transfer','Export']]) {
      const panel=node('section');panel.className='ko-panel';panel.dataset.panel=key;panel.hidden=key!=='collect';
      const tab=button(tabs,'tab-'+key,label,()=>show(key),{ready:true});tab.setAttribute('aria-controls','ko-panel-'+key);
      tab.setAttribute('aria-expanded',String(!panel.hidden));panel.id='ko-panel-'+key;
      panel.append(node('h2',label));panels[key]=panel;
    }
    function show(key) {
      for(const [name,panel] of Object.entries(panels)){panel.hidden=name!==key;host.querySelector('[data-action="tab-'+name+'"]').setAttribute('aria-expanded',String(name===key));}
    }
    function output(parent,label) {
      const section=node('section');section.setAttribute('aria-label',label);parent.append(section);outputs.push(section);return section;
    }
    function display(target,title,value) {
      target.replaceChildren(node('h3',title));const pre=node('pre',typeof value==='string'?value:JSON.stringify(value,null,2));
      if(typeof value!=='string'){pre.setAttribute('data-kb-advanced','');const hint=node('p','Details loaded. Show all writing details to inspect the exact response before continuing.');hint.className='kb-easy-only';target.append(hint);}target.append(pre);
    }
    const guidance=node('p','Add material, inspect the record, then propose a change for review. Nothing is accepted or applied just by switching views.');
    guidance.className='kb-easy-only';host.append(guidance);
    const exact=node('button','Show all writing details');exact.type='button';exact.className='kb-easy-only';exact.setAttribute('data-kb-show-advanced','');host.append(exact);
    const c=panels.collect;
    const sourceList=output(c,'Registered sources');
    async function discoverSources(cursor=null){
      return task('Loading readable source registrations…',false,async call=>{
        sourcePage=await call('source.list',{limit:25,cursor});sourceList.replaceChildren(node('h3','Registered sources'));
        sourceList.append(node('p',sourcePage.visibleTotal+' readable registrations. Availability has not been observed.'));
        const list=node('ul');list.className='review-selection';sourceList.append(list);
        for(const source of sourcePage.sources){
          const item=node('li');item.append(node('span',source.source+' · '+source.mediaType+' '));
          const select=node('button','Inspect source');select.type='button';select.dataset.source=source.source;
          select.onclick=()=>{if(controller)return;inputs.source.value=source.source;inputs.source.dispatchEvent(new Event('input'));inspectSource.click();};
          item.append(select);list.append(item);
        }
        if(!sourcePage.sources.length)sourceList.append(node('p','No readable registrations in this selection.'));
        nextSources.disabled=!sourcePage.nextCursor;
      });
    }
    const listSources=button(c,'source-list','Browse sources',()=>discoverSources());
    const nextSources=button(c,'source-next','Next sources',()=>discoverSources(sourcePage?.nextCursor));
    field(c,'source','Registered source');
    const sourceView=output(c,'Source preview');
    const inspectSource=button(c,'source-inspect','Inspect source',()=>task('Loading source registration…',false,async call=>{
      const result=await call('source.inspect',{source:inputs.source.value});
      display(sourceView,'Source registration',result);captureButton.disabled=false;
    }));
    const captureButton=button(c,'source-capture','Capture source',()=>task('Capturing the selected source…',true,async call=>{
      capture=await call('source.capture',{source:inputs.source.value,expectedSourceSha256:null});
      sourcePreview=await call('source.extraction-preview',{source:inputs.source.value,captureSha256:capture.captureSha256});
      display(sourceView,'Extraction preview',sourcePreview);extractButton.disabled=false;
    }));
    const extractButton=button(c,'source-extract','Extract text',()=>task('Extracting the captured source…',true,async call=>{
      extraction=await call('source.extract',{source:inputs.source.value,captureSha256:capture.captureSha256,expectedProfileSha256:sourcePreview.profileSha256});
      display(sourceView,'Extracted text',extraction.segments.map(segment=>segment.text).join(''));
      sourceView.append(node('p','Capture '+extraction.captureSha256+' · '+extraction.coverage));useText.disabled=false;
    }));
    const useText=button(c,'use-text','Use text in a proposal',()=>{
      if(!extraction)return;inputs.text.value=extraction.segments.map(segment=>segment.text).join('');
      inputs.evidence.value='capture:'+extraction.captureSha256;show('record');
      status.textContent=messageWithUncertainty('Source text copied into the draft. Inspect the record and review the proposed change.');
    });
    const r=panels.record;
    field(r,'record','Record ID',{value:options.record||''});field(r,'collection','Collection',{type:'select'});
    const recordView=output(r,'Record inspection');
    const loadRecord=button(r,'record-get','Inspect record',()=>task('Loading the selected record…',false,async call=>{
      selectedRecord=await call('record.get',{record:inputs.record.value});
      if(selectedRecord?.withheldRelations)throw Error('Whole-record editing is unavailable for this scope');
      const value=selectedRecord?.record;
      const capturedDraft=extraction&&inputs.evidence.value==='capture:'+extraction.captureSha256?inputs.text.value:null;
      if(value){inputs.collection.value=value.collection;inputs.title.value=value.content.title||'';inputs.text.value=value.content.text||'';}
      if(capturedDraft!==null)inputs.text.value=capturedDraft;
      recordView.replaceChildren();
      global.KBReviewCards.record(recordView,value,{title:value?'Current record':'Record unavailable or not created',revision:selectedRecord?.revision});
      if(value)global.KBReviewCards.details(recordView,'Exact record response',wires.get(selectedRecord));
      else recordView.append(node('p','A new proposal still requires permission and an unused identity.'));
      proposeButton.disabled=false;
    }));
    const vocabularyView=output(r,'Adopted vocabulary');
    const loadVocabulary=button(r,'collection-semantics','Inspect collection meaning',()=>task('Loading the adopted vocabulary…',false,async call=>{
      const result=await call('collection.semantic-inspect',{collection:inputs.collection.value});
      vocabularyView.replaceChildren();global.KBReviewCards.semantics(vocabularyView,result);
      global.KBReviewCards.details(vocabularyView,'Exact semantic declarations',wires.get(result));
    }));
    field(r,'title','Title');field(r,'text','Text',{type:'textarea'});field(r,'evidence','Evidence reference');field(r,'reason','Reason for change');
    const proposeButton=button(r,'proposal-propose','Propose change',()=>task('Preparing a native proposal…',true,async call=>{
      if(!inputs.reason.value.trim()||!inputs.evidence.value.trim()||!inputs.record.value.trim())throw Error('Record, reason and evidence are required');
      const collection=description.collections.find(value=>value.id===inputs.collection.value);if(!collection)throw Error('Select a collection');
      let result;
      if(selectedRecord?.record){
        result=await call('record.patch-propose',{record:selectedRecord.record.id,expectedRevision:selectedRecord.revision,
          requestId:crypto.randomUUID(),title:inputs.title.value,text:inputs.text.value,reason:inputs.reason.value,evidence:[inputs.evidence.value]});
      }else{
        const value={id:inputs.record.value,collection:collection.id,kind:collection.kind,
          content:{title:inputs.title.value,text:inputs.text.value},relations:[]};
        const request={id:crypto.randomUUID(),record:value.id,resource:collection.resource,mutation:'create',expectedRevision:null,
          reason:inputs.reason.value,evidence:[inputs.evidence.value],sourceResource:null};
        result=await call('proposal.propose',{request,record:value});
      }
      inputs.proposal.value=result.proposal;
      clearQueue();
      proposal=await call('proposal.inspect',{proposal:result.proposal});renderProposal();show('review');
    }));
    const v=panels.review;
    field(v,'reviewCollection','Proposal collection',{type:'select'});
    const proposalList=output(v,'Proposal queue');
    async function discoverProposals(cursor=null){
      return task('Loading readable proposals…',false,async call=>{
        proposal=null;proposalView.replaceChildren();inputs.confirmCommit.checked=false;reviewAvailability();
        proposalPage=await call('proposal.list',{collections:[inputs.reviewCollection.value],limit:25,cursor});
        proposalList.replaceChildren(node('h3','Native proposal queue'));
        proposalList.append(node('p',proposalPage.visibleTotal+' readable proposals in this collection. Inspect a proposal before deciding.'));
        const list=node('ul');list.className='review-selection';proposalList.append(list);
        for(const row of proposalPage.rows){
          const item=node('li');item.append(node('span',(row.title||row.record)+' · '+row.lifecycle.state+(row.expired?' · expired':'')+' '));
          const select=node('button','Inspect proposal');select.type='button';select.dataset.proposal=row.proposal;
          select.onclick=()=>{if(controller)return;inputs.proposal.value=row.proposal;inputs.proposal.dispatchEvent(new Event('input'));loadProposal.click();};
          item.append(select);list.append(item);
        }
        if(!proposalPage.rows.length)proposalList.append(node('p','No readable proposals in this selection.'));
        nextProposals.disabled=!proposalPage.nextCursor;
      });
    }
    const listProposals=button(v,'proposal-list','Browse proposals',()=>discoverProposals());
    const nextProposals=button(v,'proposal-next','Next proposals',()=>discoverProposals(proposalPage?.nextCursor));
    field(v,'proposal','Proposal ID');field(v,'reviewReason','Review reason');
    const proposalView=output(v,'Proposal inspection');
    const loadProposal=button(v,'proposal-inspect','Inspect proposal',()=>task('Loading the current proposal…',false,async call=>{
      proposal=await call('proposal.inspect',{proposal:inputs.proposal.value});renderProposal();
    }));
    const decisions={};
    for(const [action,label] of [['approve','Approve'],['reject','Reject'],['defer','Defer'],['withdraw','Withdraw']]) {
      decisions[action]=button(v,'proposal-'+action,label,()=>task('Recording the proposal decision…',true,async call=>{
        if(!proposal||!inputs.reviewReason.value.trim())throw Error('Inspect the proposal and provide a review reason');
        const arguments_={proposal:proposal.proposal.id,expectedProposalSha256:proposal.proposalSha256,reason:inputs.reviewReason.value};
        await call(action==='approve'?'proposal.review':'proposal.dispose',action==='approve'?arguments_:{...arguments_,action});
        clearQueue();
        proposal=await call('proposal.inspect',{proposal:inputs.proposal.value});renderProposal();
      }));
    }
    field(v,'confirmCommit','Apply this change to the authority',{type:'checkbox'});
    const commitButton=button(v,'proposal-commit','Apply change',()=>task('Applying the selected proposal…',true,async call=>{
      if(!proposal||!inputs.confirmCommit.checked)throw Error('Confirm the inspected change before applying');
      const receipt=await call('proposal.commit',{proposal:proposal.proposal.id,expectedProposalSha256:proposal.proposalSha256});
      clearQueue();
      display(proposalView,'Committed change',wires.get(receipt));proposal=null;inputs.confirmCommit.checked=false;reviewAvailability();
    }));
    function reviewAvailability() {
      const state=proposal?.lifecycle.state,open=!!proposal&&!['rejected','withdrawn','committed','committed-unattributed'].includes(state);
      for(const [action,control] of Object.entries(decisions))control.disabled=!open||(action==='approve'&&proposal.expired);
      commitButton.disabled=!open||state==='deferred'||proposal.expired;
    }
    function clearQueue(){proposalPage=null;proposalList.replaceChildren();nextProposals.disabled=true;}
    function renderProposal() {
      inputs.reviewCollection.value=proposal.proposal.record?.collection||proposal.current?.record?.collection||inputs.reviewCollection.value;
      proposalView.replaceChildren(node('h3','Proposal — '+proposal.lifecycle.state));
      global.KBReviewCards.facts(proposalView,[['Mutation',proposal.proposal.request.mutation],['Reason',proposal.proposal.request.reason],['Change evidence',proposal.proposal.request.evidence],['Expired',proposal.expired]]);
      const comparison=node('div');comparison.className='review-comparison';proposalView.append(comparison);
      global.KBReviewCards.record(comparison,proposal.current?.record,{title:'Before',revision:proposal.current?.revision});
      global.KBReviewCards.record(comparison,proposal.proposal.record,{title:'Proposed',proposed:true,revision:proposal.proposal.request.expectedRevision});
      global.KBReviewCards.details(proposalView,'Exact proposal and lifecycle',wires.get(proposal));
      inputs.confirmCommit.checked=false;reviewAvailability();
    }
    const p=panels.publish;field(p,'consumer','Registered consumer');const publicationView=output(p,'Publication preview');
    const previewPublication=button(p,'publication-preview','Preview publication',()=>task('Previewing the selected publication…',false,async call=>{
      publication=await call('publication.preview',{consumer:inputs.consumer.value});
      display(publicationView,'Selected publication',{consumer:publication.consumer,target:publication.target,
        records:publication.payload.graph.nodes.length,relationships:publication.payload.graph.edges.length,projectionSha256:publication.projectionSha256});
      publishButton.disabled=false;
    }));
    const publishButton=button(p,'publication-deliver','Publish selected view',()=>task('Publishing the selected view…',true,async call=>{
      if(!publication)throw Error('Preview the publication first');
      const receipt=await call('publication.deliver',{consumer:inputs.consumer.value,expectedProjectionSha256:publication.projectionSha256});
      display(publicationView,'Publication acknowledged',receipt);publication=null;publishButton.disabled=true;
    }));
    const t=panels.transfer;
    t.append(node('p','Export the live records you can currently read. History, pending proposals and external source files are excluded. Receiving tools still apply their own permissions.'));
    field(t,'transferPurpose','Purpose',{type:'select'});
    for(const [value,label] of [['analysis','Analysis'],['interchange','Interchange']])inputs.transferPurpose.append(new Option(label,value));
    field(t,'transferFormat','Format',{type:'select'});
    for(const [value,label] of [['brain-exchange/v1','Exchange archive — retains selected graph metadata'],['conflict-kg/v1','Conflict graph'],['calliope-kg/v1','Calliope graph']])inputs.transferFormat.append(new Option(label,value));
    const transferView=output(t,'Export preview');
    const previewTransfer=button(t,'transfer-preview','Preview export',()=>task('Computing the selected export…',false,async call=>{
      transfer=null;inputs.acknowledgeLosses.checked=false;downloadTransfer.disabled=true;
      transfer=await call('transfer.preview',{purpose:inputs.transferPurpose.value,targetFormat:inputs.transferFormat.value});
      display(transferView,'Export selection',{purpose:transfer.purpose,format:transfer.targetFormat,records:transfer.records,
        relationships:transfer.relationships,bytes:transfer.artifact.bytes,scope:transfer.scope,losses:transfer.report.losses,
        history:transfer.report.history,sourceRevision:transfer.sourceRevision});
      transferView.append(node('p',transfer.report.losses.length?'Review the listed omissions before downloading.':'No additional projection losses. The exclusions above still apply.'));
    }));
    field(t,'acknowledgeLosses','I reviewed the scope and omissions for this export',{type:'checkbox'});
    const downloadTransfer=button(t,'transfer-download','Download reviewed export',()=>task('Checking the reviewed export…',false,async (call,ensureCurrent)=>{
      const selected=transfer;
      if(!selected||!inputs.acknowledgeLosses.checked)throw Error('Review and acknowledge this export first');
      const result=await call('transfer.download',{purpose:selected.purpose,targetFormat:selected.targetFormat,
        expectedPreviewSha256:selected.previewSha256,acknowledgedLossesSha256:selected.lossesSha256});
      if(result.format!=='knowledge-transfer-download/v1'||!same(result.preview,selected)||
        result.acknowledgedLossesSha256!==selected.lossesSha256||typeof result.artifactWire!=='string')throw Error('Export selection changed');
      const bytes=new TextEncoder().encode(result.artifactWire);
      const digest=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)),b=>b.toString(16).padStart(2,'0')).join('');
      ensureCurrent();
      if(transfer!==selected||document.hidden||!inputs.acknowledgeLosses.checked||controller?.signal.aborted||
        digest!==selected.artifact.sha256||bytes.length!==selected.artifact.bytes||bytes.length>524288||
        !['brain-exchange.json','brain-graph.json'].includes(selected.artifact.filename))throw Error('Export bytes changed');
      const url=URL.createObjectURL(new Blob([bytes],{type:'application/json'})),link=node('a');
      try{link.href=url;link.download=selected.artifact.filename;link.hidden=true;host.append(link);link.click();}
      finally{link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
      transfer=null;inputs.acknowledgeLosses.checked=false;downloadTransfer.disabled=true;
      transferView.append(node('p','Reviewed export downloaded. Preview again for another download.'));
    }));
    inputs.acknowledgeLosses.addEventListener('change',()=>{
      if(controller&&!inputs.acknowledgeLosses.checked)invalidate('Export acknowledgement cleared. Preview again.');
      downloadTransfer.disabled=!transfer||!inputs.acknowledgeLosses.checked;
    });
    function clearKnowledge() {
      selectedRecord=capture=extraction=sourcePreview=proposal=publication=transfer=sourcePage=proposalPage=null;
      for(const area of outputs)area.replaceChildren();
      for(const name of ['title','text','evidence','reason','reviewReason'])inputs[name].value='';inputs.confirmCommit.checked=false;
      inputs.acknowledgeLosses.checked=false;
      for(const button of [captureButton,extractButton,useText,proposeButton,publishButton,commitButton,downloadTransfer,nextSources,nextProposals,...Object.values(decisions)])button.disabled=true;
    }
    function messageWithUncertainty(message){return uncertain?'An earlier operation may have completed. Inspect its state before retrying. '+message:message;}
    function interrupt(){
      if(controller&&activeWrite)uncertain=true;
      ++sequence;if(controller)controller.abort();controller=null;activeWrite=false;
    }
    function invalidate(message) {
      interrupt();clearKnowledge();host.removeAttribute('aria-busy');status.textContent=messageWithUncertainty(message);
    }
    async function post(request,signal) {
      const response=await fetch('/brain-operations/operate',{method:'POST',credentials:'same-origin',cache:'no-store',redirect:'error',signal,
        headers:{'content-type':'application/json'},body:JSON.stringify(request)});
      if(!response.ok||!response.body||!(response.headers.get('content-type')||'').toLowerCase().startsWith('application/json'))throw Error('Operation unavailable');
      const reader=response.body.getReader(),parts=[];let size=0;
      try{for(;;){const part=await reader.read();if(part.done)break;size+=part.value.byteLength;if(size>ceiling)throw Error('Response too large');parts.push(part.value);}}
      catch(error){await reader.cancel().catch(()=>{});throw error;}finally{reader.releaseLock();}
      const bytes=new Uint8Array(size);let offset=0;for(const part of parts){bytes.set(part,offset);offset+=part.length;}
      return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    }
    async function task(message,mayWrite,action) {
      const current=++sequence;if(controller)controller.abort();controller=new AbortController();activeWrite=mayWrite;const active=controller;
      const timer=setTimeout(()=>active.abort(),80000);host.setAttribute('aria-busy','true');status.textContent=messageWithUncertainty(message);
      function ensureCurrent(){if(current!==sequence||document.hidden||active.signal.aborted)throw Error('Selection changed');}
      async function call(operation,arguments_) {
        const request={format:['source.list','proposal.list','collection.semantic-inspect'].includes(operation)?'knowledge-operation-request/v3':operation.startsWith('transfer.')?'knowledge-operation-request/v2':'knowledge-operation-request/v1',authority:inputs.authority.value,operation,arguments:arguments_};
        const report=await post(request,active.signal),native=await validate(report,request);
        ensureCurrent();
        if(principal&&principal!==report.authorization.principal){principal=null;throw Error('Identity changed');}
        principal=report.authorization.principal;identity.textContent='Signed in as '+principal;if(native&&typeof native==='object')wires.set(native,report.nativeWire);return native;
      }
      try{await action(call,ensureCurrent);if(current===sequence)status.textContent=messageWithUncertainty('Operation completed.');}
      catch(error){if(current===sequence){if(mayWrite)uncertain=true;clearKnowledge();status.textContent=mayWrite?
        'Operation not confirmed. It may have completed. Inspect the current state before retrying.':messageWithUncertainty('Operation unavailable. Refresh the selection before continuing.');}}
      finally{clearTimeout(timer);if(current===sequence){host.removeAttribute('aria-busy');controller=null;activeWrite=false;}}
    }
    const connect=button(settings,'connect','Connect',()=>{
      invalidate('Connecting…');description=null;principal=null;
      task('Loading authority…',false,async call=>{
        description=await call('authority.inspect',{});inputs.collection.replaceChildren();inputs.reviewCollection.replaceChildren();
        for(const collection of description.collections){inputs.collection.append(new Option(collection.id+' · '+collection.kind,collection.id));inputs.reviewCollection.append(new Option(collection.id+' · '+collection.kind,collection.id));}
        for(const control of [inspectSource,loadRecord,loadProposal,previewPublication,previewTransfer,listSources,listProposals,loadVocabulary])control.disabled=false;
      });
    },{ready:true});
    inputs.authority.addEventListener('input',()=>{invalidate('Authority changed. Connect again.');description=null;principal=null;identity.textContent='';for(const control of [inspectSource,loadRecord,loadProposal,previewPublication,previewTransfer,listSources,listProposals,loadVocabulary])control.disabled=true;});
    for(const name of ['source','record','collection','reviewCollection','proposal','consumer','transferPurpose','transferFormat'])inputs[name].addEventListener('input',()=>{
      interrupt();host.removeAttribute('aria-busy');
      if(name==='source'){capture=extraction=sourcePreview=null;sourceView.replaceChildren();for(const control of [captureButton,extractButton,useText])control.disabled=true;}
      else if(name==='record'||name==='collection'){
        selectedRecord=null;recordView.replaceChildren();vocabularyView.replaceChildren();proposeButton.disabled=true;
        if(!extraction||inputs.evidence.value!=='capture:'+extraction.captureSha256){inputs.title.value='';inputs.text.value='';inputs.evidence.value='';}
      }else if(name==='reviewCollection'){proposalPage=null;proposalList.replaceChildren();nextProposals.disabled=true;proposal=null;proposalView.replaceChildren();inputs.confirmCommit.checked=false;reviewAvailability();}
      else if(name==='proposal'){proposal=null;proposalView.replaceChildren();inputs.confirmCommit.checked=false;reviewAvailability();}
      else if(name==='consumer'){publication=null;publicationView.replaceChildren();publishButton.disabled=true;}
      else {transfer=null;transferView.replaceChildren();inputs.acknowledgeLosses.checked=false;downloadTransfer.disabled=true;}
      status.textContent=messageWithUncertainty('Selection changed. Inspect it before continuing.');
    });
    document.addEventListener('visibilitychange',()=>{if(document.hidden)invalidate('Preview cleared. Inspect the selection when you return.');});
    global.addEventListener('pagehide',()=>invalidate('Preview cleared.'));
    host.append(settings,status,identity,tabs,...Object.values(panels));
    return {clear:()=>invalidate('Preview cleared.'),connect:()=>connect.click()};
  }
  global.KnowledgeOperations={mount,validate};
  if(typeof document!=='undefined')document.addEventListener('DOMContentLoaded',()=>{
    const hosts=document.querySelectorAll('[data-kb-knowledge-operations]');
    if(!hosts.length)return;
    Promise.resolve(global.KBShell?global.KBShell.mount({title:'Knowledge workbench'}):null)
      .then(()=>hosts.forEach(host=>mount(host)))
      .catch(()=>hosts.forEach(host=>{host.textContent='Knowledge workbench unavailable.';}));
  });
})(typeof window!=='undefined'?window:globalThis);
