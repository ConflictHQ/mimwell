/* Optional composable workbench. The selected host owns identity and writers. */
(function(global) {
  'use strict';
  const ceiling=4194304;
  const node=(tag,text)=>{const el=document.createElement(tag);if(text!=null)el.textContent=text;return el;};
  const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
  const same=(a,b)=>canonical(a)===canonical(b);
  async function validate(report,request) {
    if(!['knowledge-operation-request/v1','knowledge-operation-request/v2','knowledge-operation-request/v3','knowledge-operation-request/v4','knowledge-operation-request/v5','knowledge-operation-request/v6'].includes(request.format)||
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
    let capabilities=null;
    const requiredOperations={
      'source-list':['source.list'],'source-next':['source.list'],'source-inspect':['source.inspect'],
      'source-capture':['source.capture','source.extraction-preview'],'source-extract':['source.extract'],
      'record-get':['record.get'],'collection-semantics':['collection.semantic-inspect'],
      'record-history':['record.history'],
      'proposal-list':['proposal.list'],'proposal-next':['proposal.list'],'proposal-inspect':['proposal.inspect'],
      'proposal-approve':['proposal.review'],'proposal-reject':['proposal.dispose'],'proposal-defer':['proposal.dispose'],
      'proposal-withdraw':['proposal.dispose'],'proposal-commit':['proposal.commit'],
      'publication-preview':['publication.preview'],'publication-deliver':['publication.deliver'],
      'transfer-preview':['transfer.preview'],'transfer-download':['transfer.download'],
      'file-inspect':['file.inspect'],'file-history':['file.history'],'file-propose':['file.propose'],
      'file-proposal-inspect':['file.proposal-inspect'],'file-review':['file.review'],'file-publish':['file.publish'],
      'file-group-inspect':['file.group.inspect'],'file-group-propose':['file.group.propose'],
      'file-group-propose-binary':['file.group.propose-binary'],'file-group-proposal-inspect':['file.group.proposal-inspect'],
      'file-group-review':['file.group.review'],'file-group-status':['file.group.status'],
      'file-group-publish':['file.group.destination-publish']
    };
    let sequence=0, controller=null, activeWrite=false, uncertain=false, principal=null, description=null, selectedRecord=null,
      capture=null, extraction=null, sourcePreview=null, proposal=null, publication=null, transfer=null, sourcePage=null, proposalPage=null,
      fileSource=null, fileProposal=null, fileHistory=null, fileAttempt=null;
    const inputs={}, buttons=[], outputs=[];
    const status=node('p','Choose the brain you are allowed to change, then connect to begin.');status.setAttribute('role','status');
    const identity=node('p');identity.className='ko-coordinate';
    const capabilityView=node('section');capabilityView.className='ko-panel ko-capabilities';capabilityView.hidden=true;capabilityView.setAttribute('aria-label','Available actions');
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
    function syncCapabilities(){
      for(const control of buttons){
        const required=requiredOperations[control.dataset.action];
        if(required&&(!capabilities||required.some(operation=>!capabilities.operations.includes(operation))))control.disabled=true;
      }
      if(!capabilities||!['proposal.propose','record.patch-propose'].some(operation=>capabilities.operations.includes(operation)))proposeButton.disabled=true;
      const canDraft=capabilities&&['proposal.propose','record.patch-propose'].some(operation=>capabilities.operations.includes(operation));
      for(const name of ['title','text','reason','evidence'])inputs[name].disabled=!canDraft;
    }
    const tabs=node('nav');tabs.className='ko-tabs';tabs.setAttribute('aria-label','Knowledge tasks');
    const panels={};
    for(const [key,label] of [['collect','Collect'],['record','Record'],['review','Review'],['publish','Publish'],['transfer','Export'],['files','Files']]) {
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
    const historyView=output(r,'Record revision history');
    const loadHistory=button(r,'record-history','Browse recorded revisions',()=>task('Loading recorded revisions…',false,async call=>{
      const history=await call('record.history',{record:inputs.record.value,limit:25});
      historyView.replaceChildren(node('h3','Recorded revisions'));
      if(!history){historyView.append(node('p','Record history unavailable.'));return;}
      historyView.append(node('p','Current revision: '+history.revision),node('p','Earlier history: '+history.priorHistory+'. Historical content is not included in this view.'));
      const list=node('ul');historyView.append(list);
      for(const entry of history.entries){
        const row=node('li',entry.at+' · '+entry.mutation+' · '+entry.revision+' ');
        if(entry.proposal&&capabilities.operations.includes('proposal.inspect')){
          const inspect=node('button','Inspect reviewed change');inspect.type='button';
          inspect.onclick=()=>{if(controller)return;inputs.proposal.value=entry.proposal;inputs.proposal.dispatchEvent(new Event('input'));show('review');loadProposal.click();};row.append(inspect);
        }
        list.append(row);
      }
      if(history.truncated)historyView.append(node('p','Showing the latest '+history.limit+' recorded revisions.'));
      if(!history.entries.length)historyView.append(node('p','No changes have been recorded since import.'));
    }));
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
      syncCapabilities();
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
    for(const [value,label] of [['brain-exchange/v1','Exchange archive — retains selected graph metadata'],['mimwell-kg/v1','Mimwell graph']])inputs.transferFormat.append(new Option(label,value));
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
      syncCapabilities();
    });
    const f=panels.files;
    f.append(node('p','Edit a host-registered source through its declared writer and content policy. Opaque binary assets and fixed two-to-four destination groups are supported when the host registers them. A different host identity reviews each proposal; each destination creates only a local review branch. No default branch or remote service is updated. If a response is interrupted, inspect its proposal and destination status before retrying.'));
    const fileView=output(f,'Registered file source');
    const inspectFile=button(f,'file-inspect','Inspect registered source',()=>task('Inspecting the registered file source…',false,async call=>{
      fileSource=await call('file.inspect',{});fileProposal=null;fileHistory=null;
      const binary=fileSource.writer==='binary-commit';
      inputs.fileDocument.parentElement.hidden=binary;inputs.fileAsset.parentElement.hidden=!binary;
      inputs.fileDocument.value=binary?'':fileSource.documentWire;inputs.fileAsset.value='';
      display(fileView,'Registered source',fileSource);
      fileHistoryButton.disabled=!capabilities?.operations.includes('file.history');
      fileProposeButton.disabled=!capabilities?.operations.includes('file.propose');
    }));
    const fileHistoryButton=button(f,'file-history','Browse source history',()=>task('Loading source history…',false,async call=>{
      if(!fileSource)throw Error('Inspect the registered source first');
      fileHistory=await call('file.history',{limit:25});
      display(fileView,'Source history',fileHistory);
    }));
    field(f,'fileDocument','Proposed file content',{type:'textarea'});
    field(f,'fileAsset','Opaque binary asset to propose',{type:'file'});
    inputs.fileAsset.parentElement.hidden=true;
    field(f,'fileReason','Reason for file change');
    field(f,'fileProposalId','File proposal ID');
    inputs.fileProposalId.addEventListener('input',()=>{
      if(fileProposal&&inputs.fileProposalId.value.trim()!==fileProposal.id){
        fileProposal=null;fileView.replaceChildren();fileReview.disabled=true;filePublish.disabled=true;
      }
      fileProposalInspect.disabled=!capabilities?.operations.includes('file.proposal-inspect')||!inputs.fileProposalId.value.trim();
    });
    const fileProposeButton=button(f,'file-propose','Create review proposal',()=>task('Creating a schema-checked file proposal…',true,async call=>{
      if(!fileSource||!inputs.fileReason.value.trim())throw Error('Inspect the source and provide a reason');
      if(fileSource.writer==='binary-commit'){
        const file=inputs.fileAsset.files?.[0];if(!file)throw Error('Choose one bounded binary asset');
        if(file.size>524288)throw Error('Binary asset exceeds the 512 KiB limit');
        const bytes=new Uint8Array(await file.arrayBuffer());let binary='';
        for(let offset=0;offset<bytes.length;offset+=0x8000)binary+=String.fromCharCode(...bytes.subarray(offset,offset+0x8000));
        fileAttempt={id:crypto.randomUUID(),revision:fileSource.revision};
        fileProposal=await call('file.propose-binary',{expectedRevision:fileAttempt.revision,
          requestId:fileAttempt.id,reason:inputs.fileReason.value,contentBase64:btoa(binary)});
      }else{
        fileAttempt={id:crypto.randomUUID(),revision:fileSource.revision};
        fileProposal=await call('file.propose',{expectedRevision:fileAttempt.revision,
          requestId:fileAttempt.id,reason:inputs.fileReason.value,documentWire:inputs.fileDocument.value});
      }
      fileAttempt=null;inputs.fileProposalId.value=fileProposal.id;
      display(fileView,'Proposed file change',fileProposal);fileProposalInspect.disabled=false;
    }));
    const fileReconcile=button(f,'file-reconcile','Inspect uncertain proposal',()=>task('Checking the existing file proposal…',false,async call=>{
      if(!fileAttempt)throw Error('No uncertain file proposal is available');
      fileProposal=await call('file.proposal-inspect',{proposal:fileAttempt.id});fileAttempt=null;uncertain=false;
      inputs.fileProposalId.value=fileProposal.id;
      display(fileView,'Reconciled proposal',fileProposal);fileProposalInspect.disabled=false;
    }));
    const fileProposalInspect=button(f,'file-proposal-inspect','Inspect proposal',()=>task('Inspecting the current file proposal…',false,async call=>{
      const id=inputs.fileProposalId.value.trim();
      if(!id)throw Error('Enter a file proposal ID first');
      fileProposal=await call('file.proposal-inspect',{proposal:id});display(fileView,'Current proposal',fileProposal);
      fileReview.disabled=!capabilities?.operations.includes('file.review');
      filePublish.disabled=!capabilities?.operations.includes('file.publish')||fileProposal.stale!==false||!Array.isArray(fileProposal.reviewers)||fileProposal.reviewers.length===0;
    }));
    field(f,'fileReviewReason','Independent review reason');
    const fileReview=button(f,'file-review','Review proposal',()=>task('Recording the independent review…',true,async call=>{
      if(!fileProposal||!inputs.fileReviewReason.value.trim())throw Error('Inspect the proposal and provide a review reason');
      await call('file.review',{proposal:fileProposal.id,expectedProposalSha256:fileProposal.proposalSha256,
        reason:inputs.fileReviewReason.value});
      fileProposal=await call('file.proposal-inspect',{proposal:fileProposal.id});display(fileView,'Reviewed proposal',fileProposal);
      filePublish.disabled=!capabilities?.operations.includes('file.publish');
    }));
    const filePublish=button(f,'file-publish','Create local review branch',()=>task('Publishing the reviewed proposal to a local review branch…',true,async call=>{
      if(!fileProposal)throw Error('Inspect and independently review the proposal first');
      const receipt=await call('file.publish',{proposal:fileProposal.id,expectedProposalSha256:fileProposal.proposalSha256});
      display(fileView,'Local review branch created',receipt);fileProposal=null;filePublish.disabled=true;fileProposalInspect.disabled=true;
    }));
    const groupView=output(f,'Registered publication group');
    let groupSnapshot=null,groupProposal=null,groupRequestId=null,groupStatuses=[];
    const groupInspect=button(f,'file-group-inspect','Inspect registered publication group',()=>task('Inspecting all registered destinations…',false,async call=>{
      groupSnapshot=await call('file.group.inspect',{});groupProposal=null;groupStatuses=[];
      const binary=groupSnapshot.writer==='binary-commit';
      inputs.fileGroupDocument.parentElement.hidden=binary;inputs.fileGroupAsset.parentElement.hidden=!binary;
      display(groupView,'Selected local destinations',groupSnapshot);
      groupPropose.disabled=!capabilities?.operations.includes(groupSnapshot.writer==='binary-commit'?'file.group.propose-binary':'file.group.propose');
    }));
    field(f,'fileGroupDocument','Group text content',{type:'textarea'});
    field(f,'fileGroupAsset','Binary asset to publish',{type:'file'});
    field(f,'fileGroupReason','Reason for group publication');
    field(f,'fileGroupProposalId','Group proposal ID');
    const groupPropose=button(f,'file-group-propose','Propose to all selected destinations',()=>task('Creating one reviewed proposal for the selected destinations…',true,async call=>{
      if(!groupSnapshot||!inputs.fileGroupReason.value.trim())throw Error('Inspect the group and provide a reason first');
      const shared={expectedGroupRevision:groupSnapshot.groupRevision,expectedAuthorizationSha256:groupSnapshot.authorizationSha256,
        reason:inputs.fileGroupReason.value};
      if(groupSnapshot.writer==='binary-commit'){
        const file=inputs.fileGroupAsset.files?.[0];if(!file)throw Error('Choose one bounded binary asset');
        if(file.size>524288)throw Error('Binary asset exceeds the 512 KiB limit');
        const bytes=new Uint8Array(await file.arrayBuffer());let binary='';
        for(let offset=0;offset<bytes.length;offset+=0x8000)binary+=String.fromCharCode(...bytes.subarray(offset,offset+0x8000));
        shared.contentBase64=btoa(binary);
        groupRequestId=crypto.randomUUID();shared.requestId=groupRequestId;groupReconcile.disabled=false;
        groupProposal=await call('file.group.propose-binary',shared);
      }else{
        shared.documentWire=inputs.fileGroupDocument.value;
        groupRequestId=crypto.randomUUID();shared.requestId=groupRequestId;groupReconcile.disabled=false;
        groupProposal=await call('file.group.propose',shared);
      }
      inputs.fileGroupProposalId.value=groupProposal.id;display(groupView,'Group proposal awaiting independent review',groupProposal);
      groupProposalInspect.disabled=false;
    }));
    const groupReconcile=button(f,'file-group-reconcile','Inspect uncertain group proposal',()=>task('Reconciling the existing group request…',false,async call=>{
      if(!groupRequestId)throw Error('No uncertain group request is available');
      groupProposal=await call('file.group.proposal-inspect',{proposal:groupRequestId});
      inputs.fileGroupProposalId.value=groupProposal.id;display(groupView,'Reconciled group proposal',groupProposal);
      groupStatus.disabled=false;groupReview.disabled=!capabilities?.operations.includes('file.group.review')||groupProposal.stale!==false;
      groupProposalInspect.disabled=false;uncertain=false;
    }));
    const groupProposalInspect=button(f,'file-group-proposal-inspect','Inspect group proposal',()=>task('Inspecting the selected group proposal…',false,async call=>{
      const id=inputs.fileGroupProposalId.value.trim();if(!id)throw Error('Enter a group proposal ID first');
      groupProposal=await call('file.group.proposal-inspect',{proposal:id});display(groupView,'Group proposal',groupProposal);
      groupReview.disabled=!capabilities?.operations.includes('file.group.review')||groupProposal.stale!==false;
      groupStatus.disabled=!capabilities?.operations.includes('file.group.status');
    }));
    inputs.fileGroupProposalId.addEventListener('input',()=>{
      groupRequestId=inputs.fileGroupProposalId.value.trim()||null;groupProposal=null;
      groupProposalInspect.disabled=!capabilities?.operations.includes('file.group.proposal-inspect')||!groupRequestId;
      groupReview.disabled=true;groupStatus.disabled=true;
    });
    field(f,'fileGroupReviewReason','Independent group review reason');
    const groupReview=button(f,'file-group-review','Independently review group proposal',()=>task('Recording independent review of the exact group proposal…',true,async call=>{
      if(!groupProposal||!inputs.fileGroupReviewReason.value.trim())throw Error('Inspect the group proposal and provide a review reason');
      await call('file.group.review',{proposal:groupProposal.id,expectedProposalSha256:groupProposal.proposalSha256,reason:inputs.fileGroupReviewReason.value});
      groupProposal=await call('file.group.proposal-inspect',{proposal:groupProposal.id});display(groupView,'Reviewed group proposal',groupProposal);
      groupStatus.disabled=false;
    }));
    const groupStatus=button(f,'file-group-status','Reconcile destination publication status',()=>task('Checking each destination ref independently…',false,async call=>{
      if(!groupProposal)throw Error('Inspect a group proposal first');
      groupStatuses=await call('file.group.status',{proposal:groupProposal.id});
      groupView.replaceChildren(node('h3','Independent destination status'));
      groupView.append(node('p','Proposal reason: '+(groupProposal.reason||'No reason recorded.')));
      groupView.append(node('p','Each destination is checked and published independently.'));
      for(const destination of groupStatuses.destinations){
        const row=node('section');row.dataset.destinationStatus=destination.state;row.dataset.destination=destination.id;
        row.setAttribute('aria-label',destination.id+' status');
        row.append(node('h4',destination.id));
        row.append(node('p','Status: '+destination.state));
        if(destination.reason)row.append(node('p','Reason: '+destination.reason));
        if(destination.state==='published')row.append(node('p','Published to the registered local review branch.'));
        else if(destination.state==='pending'&&groupProposal.reviewers?.some(reviewer=>reviewer!==groupProposal.author))row.append(node('p','Action available: publish this reviewed destination.'));
        else if(destination.state==='pending')row.append(node('p','Pending independent review; publication is not available yet.'));
        else if(destination.state==='outcome-unknown')row.append(node('p','Action available: reconcile the existing attempt before retrying.'));
        else row.append(node('p','No publication action is available until the refusal is resolved.'));
        if(destination.state==='pending'&&groupProposal.reviewers?.some(reviewer=>reviewer!==groupProposal.author)){
          const publish=button(row,'file-group-publish','Create local review branch for '+destination.id,()=>task('Publishing one reviewed destination with compare-and-swap…',true,async publishCall=>{
            const receipt=await publishCall('file.group.destination-publish',{proposal:groupProposal.id,
              expectedProposalSha256:groupProposal.proposalSha256,destination:destination.id});
            row.append(node('pre',JSON.stringify(receipt,null,2)));publish.disabled=true;
          }));publish.disabled=!capabilities?.operations.includes('file.group.destination-publish');
        }
        groupView.append(row);
      }
      groupView.append(node('p','Each destination is a separate local compare-and-swap. Reconcile after an interrupted response; there is no cross-repository atomicity.'));
    }));
    function clearKnowledge() {
      selectedRecord=capture=extraction=sourcePreview=proposal=publication=transfer=sourcePage=proposalPage=fileSource=fileProposal=fileHistory=null;
      for(const area of outputs)area.replaceChildren();
      for(const name of ['title','text','evidence','reason','reviewReason'])inputs[name].value='';inputs.confirmCommit.checked=false;
      if(inputs.fileDocument)inputs.fileDocument.value='';if(inputs.fileAsset)inputs.fileAsset.value='';
      if(inputs.fileDocument)inputs.fileDocument.parentElement.hidden=false;if(inputs.fileAsset)inputs.fileAsset.parentElement.hidden=true;
      if(inputs.fileReason)inputs.fileReason.value='';if(inputs.fileProposalId)inputs.fileProposalId.value='';if(inputs.fileReviewReason)inputs.fileReviewReason.value='';
      if(inputs.fileGroupDocument)inputs.fileGroupDocument.value='';if(inputs.fileGroupAsset)inputs.fileGroupAsset.value='';
      if(inputs.fileGroupDocument)inputs.fileGroupDocument.parentElement.hidden=false;if(inputs.fileGroupAsset)inputs.fileGroupAsset.parentElement.hidden=true;
      if(inputs.fileGroupReason)inputs.fileGroupReason.value='';if(inputs.fileGroupProposalId)inputs.fileGroupProposalId.value='';
      inputs.acknowledgeLosses.checked=false;
      for(const button of [captureButton,extractButton,useText,proposeButton,publishButton,commitButton,downloadTransfer,nextSources,nextProposals,
        fileHistoryButton,fileProposeButton,fileReconcile,fileProposalInspect,fileReview,filePublish,groupPropose,groupReconcile,
        groupProposalInspect,groupReview,groupStatus,...Object.values(decisions)])button.disabled=true;
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
        if(operation!=='authority.inspect'&&(!capabilities||!capabilities.operations.includes(operation)))throw Error('This action is unavailable for this connection');
        const request={format:operation.startsWith('file.')?'knowledge-operation-request/v6':['source.list','proposal.list','collection.semantic-inspect'].includes(operation)?'knowledge-operation-request/v3':operation.startsWith('transfer.')?'knowledge-operation-request/v2':'knowledge-operation-request/v1',authority:inputs.authority.value,operation,arguments:arguments_};
        const report=await post(request,active.signal),native=await validate(report,request);
        ensureCurrent();
        if(principal&&principal!==report.authorization.principal){principal=null;throw Error('Identity changed');}
        if(operation==='authority.inspect'){
          const advertised=report.hostCapabilities;
          if(advertised?.format!=='authoring-capabilities/v1'||advertised.authority!==request.authority||
            advertised.principal!==report.authorization.principal||advertised.binding!==report.contract||
            advertised.authorization!=='host-registration-only'||advertised.nativePolicy!=='required-per-operation'||
            advertised.executionAuthorized!==false||!Array.isArray(advertised.operations)||advertised.operations.length>64||
            advertised.operations.some(value=>typeof value!=='string'||value.length>100)||
            new Set(advertised.operations).size!==advertised.operations.length)throw Error('Action discovery unavailable');
          capabilities=advertised;
        }
        principal=report.authorization.principal;identity.textContent='Signed in as '+principal;if(native&&typeof native==='object')wires.set(native,report.nativeWire);return native;
      }
      try{await action(call,ensureCurrent);if(current===sequence)status.textContent=messageWithUncertainty('Operation completed.');}
      catch(error){if(current===sequence){if(mayWrite)uncertain=true;clearKnowledge();
        if(fileAttempt)fileReconcile.disabled=false;
        if(groupRequestId)groupReconcile.disabled=false;
        status.textContent=mayWrite?
        'Operation not confirmed. It may have completed. Inspect the current state before retrying.':messageWithUncertainty('Operation unavailable. Refresh the selection before continuing.');}}
      finally{clearTimeout(timer);if(current===sequence){host.removeAttribute('aria-busy');controller=null;activeWrite=false;syncCapabilities();}}
    }
    const connect=button(settings,'connect','Connect',()=>{
      invalidate('Connecting…');groupRequestId=null;groupProposal=null;groupSnapshot=null;description=null;principal=null;capabilities=null;capabilityView.hidden=true;capabilityView.replaceChildren();
      task('Loading authority…',false,async call=>{
        description=await call('authority.inspect',{});inputs.collection.replaceChildren();inputs.reviewCollection.replaceChildren();
        capabilityView.append(node('h2','Available actions'),node('p','These actions were offered when you connected. Permission is checked again for every record and operation.'));
        const actions=node('ul');capabilityView.append(actions);
        for(const [label,operations] of [['Collect source material',['source.inspect','source.capture','source.extraction-preview','source.extract']],
          ['Edit existing records',['record.get','record.patch-propose']],['Create records',['record.get','proposal.propose']],
          ['Review suggestions',['proposal.inspect','proposal.review']],['Apply reviewed changes',['proposal.inspect','proposal.commit']],
          ['Publish a selected view',['publication.preview','publication.deliver']],
          ['Edit registered sources',['file.inspect','file.propose']],
          ['Review registered file changes',['file.proposal-inspect','file.review']],
          ['Create local file review branches',['file.proposal-inspect','file.publish']],
          ['Propose to a registered destination group',['file.group.propose','file.group.destination-publish']],
          ['Propose opaque assets to a registered destination group',['file.group.propose-binary','file.group.destination-publish']]]){
          actions.append(node('li',label+': '+(operations.every(operation=>capabilities.operations.includes(operation))?'offered':'unavailable')));
        }
        capabilityView.append(node('p','Only exact paths and destinations registered by this host can be changed. Group destinations publish independently, so a partial result must be reconciled before continuing.'));
        capabilityView.hidden=false;
        for(const collection of description.collections){inputs.collection.append(new Option(collection.id+' · '+collection.kind,collection.id));inputs.reviewCollection.append(new Option(collection.id+' · '+collection.kind,collection.id));}
        for(const control of [inspectSource,loadRecord,loadHistory,loadProposal,previewPublication,previewTransfer,listSources,listProposals,loadVocabulary,inspectFile])control.disabled=false;
        groupInspect.disabled=!capabilities?.operations.includes('file.group.inspect');
      });
    },{ready:true});
    inputs.authority.addEventListener('input',()=>{fileAttempt=null;groupRequestId=null;groupProposal=null;groupSnapshot=null;invalidate('Authority changed. Connect again.');description=null;principal=null;capabilities=null;capabilityView.hidden=true;capabilityView.replaceChildren();identity.textContent='';for(const control of [inspectSource,loadRecord,loadHistory,loadProposal,previewPublication,previewTransfer,listSources,listProposals,loadVocabulary,inspectFile,fileReconcile,groupInspect])control.disabled=true;syncCapabilities();});
    for(const name of ['source','record','collection','reviewCollection','proposal','consumer','transferPurpose','transferFormat'])inputs[name].addEventListener('input',()=>{
      interrupt();host.removeAttribute('aria-busy');
      if(name==='source'){capture=extraction=sourcePreview=null;sourceView.replaceChildren();for(const control of [captureButton,extractButton,useText])control.disabled=true;}
      else if(name==='record'||name==='collection'){
        selectedRecord=null;recordView.replaceChildren();vocabularyView.replaceChildren();historyView.replaceChildren();proposeButton.disabled=true;
        if(!extraction||inputs.evidence.value!=='capture:'+extraction.captureSha256){inputs.title.value='';inputs.text.value='';inputs.evidence.value='';}
      }else if(name==='reviewCollection'){proposalPage=null;proposalList.replaceChildren();nextProposals.disabled=true;proposal=null;proposalView.replaceChildren();inputs.confirmCommit.checked=false;reviewAvailability();}
      else if(name==='proposal'){proposal=null;proposalView.replaceChildren();inputs.confirmCommit.checked=false;reviewAvailability();}
      else if(name==='consumer'){publication=null;publicationView.replaceChildren();publishButton.disabled=true;}
      else {transfer=null;transferView.replaceChildren();inputs.acknowledgeLosses.checked=false;downloadTransfer.disabled=true;}
      status.textContent=messageWithUncertainty('Selection changed. Inspect it before continuing.');
    });
    document.addEventListener('visibilitychange',()=>{if(document.hidden)invalidate('Preview cleared. Inspect the selection when you return.');});
    global.addEventListener('pagehide',()=>invalidate('Preview cleared.'));
    host.append(settings,status,identity,capabilityView,tabs,...Object.values(panels));
    syncCapabilities();
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
