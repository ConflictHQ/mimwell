/* Shared typed review views. Source references stay inert; no writer or fetch here. */
(function(global){
  'use strict';
  const node=(tag,text)=>{const el=document.createElement(tag);if(text!=null)el.textContent=text;return el;};
  const imprecise=item=>typeof item==='number'&&(!Number.isFinite(item)||(Number.isInteger(item)&&!Number.isSafeInteger(item)));
  function value(item){
    if(imprecise(item))return 'Large numeric value — inspect the exact payload';
    return item==null?'Not supplied':typeof item==='object'?JSON.stringify(item,(_key,v)=>imprecise(v)?'Large numeric value — inspect the exact payload':v,2):String(item);
  }
  function facts(parent,entries){
    const list=node('dl');list.className='review-facts';
    for(const [label,item] of entries){
      const term=node('dt',label), description=node('dd',value(item));
      if(['Identity','Revision','Diagnostic ID','Authority','Contract','Participant','Ontology','Original lineages','Source revisions'].includes(label)){term.setAttribute('data-kb-advanced','');description.setAttribute('data-kb-advanced','');}
      list.append(term,description);
    }
    parent.append(list);
  }
  function details(parent,label,text){const section=node('details');section.setAttribute('data-kb-advanced','');section.append(node('summary',label),node('pre',text));parent.append(section);}
  function record(parent,record,{title='Record',revision=null,proposed=false}={}){
    const card=node('article');card.className='review-card';card.append(node('h3',title));parent.append(card);
    if(!record){card.append(node('p','No record in this observation.'));return;}
    const content=record.content||record;
    if(global.KBEasyView){const summary=node('div');summary.innerHTML=global.KBEasyView.summaryHtml({...record,proposed});card.append(summary);}
    card.append(node('h4',typeof content.title==='string'?content.title:record.id));
    facts(card,[['Identity',record.id],['Kind',record.kind],['Collection',record.collection],['Revision',revision]]);
    if(typeof content.text==='string')card.append(node('p',content.text));
    if(typeof content.description==='string')card.append(node('p',content.description));
    for(const key of ['source','path','origin'])if(record[key]!=null)facts(card,[[key,record[key]]]);
    const links=record.relations||[];
    if(links.length){
      const list=node('ul');card.append(node('h4',proposed?'Proposed relationships':'Recorded relationships'),list);
      for(const link of links)list.append(node('li',link.rel+' → '+value(link.target)));
      card.append(node('p','Names and aliases do not establish shared identity. Preserve each source and its provenance.'));
    }
    evidence(card,record.evidence);
  }
  function evidence(parent,bundle){
    const section=node('section');section.className='review-evidence';section.append(node('h4','Evidence'));parent.append(section);
    if(!bundle){section.append(node('p','Evidence not supplied in this record.'));return;}
    const assertions=bundle.assertions||[];
    section.append(node('p',assertions.length+' assertions in this observation.'));
    for(const assertion of assertions){
      const row=node('article');row.className='review-assertion';row.append(node('h5',assertion.id));
      facts(row,[['Field',assertion.field],['Value',assertion.value],['Status',assertion.status]]);
      for(const relation of ['supersedes','retracts','contradicts'])if(assertion[relation]?.length)facts(row,[[relation,assertion[relation].join(', ')]]);
      section.append(row);
    }
    const sources=node('details'),attestations=node('details');
    sources.setAttribute('data-kb-advanced','');attestations.setAttribute('data-kb-advanced','');
    sources.append(node('summary','Source lineage ('+(bundle.sources||[]).length+')'));
    attestations.append(node('summary','Attestations ('+(bundle.attestations||[]).length+')'));
    for(const source of bundle.sources||[])facts(sources,[['Source',source.id],['Revision',source.revision],['Original lineage',source.lineage],['Reference',source.path]]);
    for(const attestation of bundle.attestations||[])facts(attestations,[['Attestation',attestation.id],['Assertion',attestation.assertion],['Representation',attestation.representation],['Locator',attestation.locator],['Declared review',attestation.review?.state]]);
    section.append(sources,attestations);
    section.append(node('p','References describe provenance. Access and review declarations must be checked before use.'));
  }
  function findings(parent,report){
    parent.append(node('h3','Findings to review'),node('p','These are diagnostics over the selected context. They do not approve changes or settle conflicting claims.'));
    parent.append(node('p','Finding limits: '+(report.truncation.join(', ')||'none reported')+' · Context limits: '+(report.coverage.contextTruncation.join(', ')||'none reported')));
    if(!report.proposals.length)parent.append(node('p','No findings in this bounded observation. Semantic completeness is not assessed.'));
    for(const finding of report.proposals){
      const card=node('details');card.className='review-card';card.dataset.finding=finding.id;
      card.append(node('summary',finding.rule.replaceAll('-',' ')+' · '+finding.assertions.length+' assertions'),node('p',finding.action));
      facts(card,[['Diagnostic ID',finding.id],['Records',finding.records],['Assertions',finding.assertions],['Original lineages',finding.originalLineages]]);
      const citations=node('details');citations.append(node('summary','Evidence references ('+finding.citations.length+')'));
      for(const citation of finding.citations)facts(citations,[['Assertion',citation.assertion],['Source revisions',citation.sourceRevisions],['Reference',citation.href],['Locator',citation.locator],['Observed status',citation.status],['Declared review',citation.reviewState]]);
      card.append(citations);
      parent.append(card);
    }
    parent.append(node('p','Correct knowledge through its owning collection and participant. Reinspect after a correction; this captured finding is not a continuing access grant.'));
  }
  function semantics(parent,result){
    parent.append(node('h3','Adopted meaning and identity'));
    facts(parent,[['Authority',result.owner.authority],['Contract',result.owner.contract],['Participant',result.owner.participant],['Ontology',result.ontology],['Kind',result.kind.id],['Meaning',result.kind.description],['Identity convention',result.identity.convention]]);
    parent.append(node('p',result.writer.instruction));
    details(parent,'Identity declaration',value(result.identity.declaration));
    const terms=node('details');terms.append(node('summary','Declared vocabulary ('+result.taxonomy.length+')'));
    for(const term of result.taxonomy)facts(terms,[['Term',term.id],['Label',term.label],['Definition',term.definition],['Declared aliases',term.aliases],['Broader terms',term.broader]]);
    parent.append(terms,node('p',result.taxonomyChange.instruction));
  }
  global.KBReviewCards={record,evidence,findings,semantics,details,facts};
})(window);
