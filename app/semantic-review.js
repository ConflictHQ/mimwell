/* Diagnostic review composed from the existing exact context inspector. */
(function(global){
  'use strict';
  const canonical=value=>Array.isArray(value)?'['+value.map(canonical).join(',')+']':value&&typeof value==='object'?'{'+Object.keys(value).sort().map(key=>JSON.stringify(key)+':'+canonical(value[key])).join(',')+'}':JSON.stringify(value);
  const same=(a,b)=>canonical(a)===canonical(b);
  async function sha(text){return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(text))),b=>b.toString(16).padStart(2,'0')).join('');}
  async function validate(report){
    if(report?.format!=='semantic-review/v1'||report.executionAuthorized!==false||typeof report.findingsWire!=='string'||!/^[a-f0-9]{64}$/.test(report.findingsSha256))throw Error('Invalid semantic review');
    const checked=await global.KBContextInspection.validate(report.inspection),findings=report.findings;
    if(new TextEncoder().encode(report.findingsWire).length>262144||await sha(report.findingsWire)!==report.findingsSha256||
      !same(JSON.parse(report.findingsWire),findings)||findings?.format!=='maintenance-proposals/v1'||
      findings.contextSha256!==await sha(checked.captured.payload.slice(0,-1))||
      !same(findings.basis,checked.payload.request)||!same(findings.authorization,checked.payload.authorization)||
      !Array.isArray(findings.proposals)||!Array.isArray(findings.truncation)||
      !same(findings.coverage?.contextTruncation,checked.payload.truncation))throw Error('Mismatched semantic findings');
    for(const finding of findings.proposals)if(finding.status!=='proposed'||finding.requiresReview!==true||
      !Array.isArray(finding.records)||!Array.isArray(finding.assertions)||!Array.isArray(finding.citations)||!Array.isArray(finding.originalLineages))throw Error('Invalid finding');
    return {...checked,findings,findingsWire:report.findingsWire};
  }
  function render(content,checked){
    const cards=global.KBReviewCards;
    for(const record of checked.payload.nodes)cards.record(content,record,{title:'Context record'});
    for(const reference of checked.payload.references){
      const section=document.createElement('section');content.append(section);
      cards.facts(section,[['Reference',reference.address],['Observed status',reference.status],['Target',reference.target]]);
      if(reference.status==='resolved')cards.record(section,reference.record,{title:'Resolved participant record',revision:reference.revision});
    }
    cards.findings(content,checked.findings);
    cards.details(content,'Exact diagnostic findings',checked.findingsWire);
    const link=document.createElement('a');link.href='/knowledge-workbench/';link.textContent='Open the knowledge workbench to select a native authority and propose a correction';content.append(link);
    const guidance=document.createElement('p');guidance.textContent='For file-owned records, correct the declared source through its versioned editing workflow. Identity and term changes require the adopted ontology and the owning participant; a similar name is not a merge instruction.';content.append(guidance);
  }
  global.KBSemanticReview={validate,render};
  document.addEventListener('DOMContentLoaded',()=>{
    const host=document.querySelector('[data-kb-semantic-review]');if(!host)return;
    Promise.resolve(global.KBShell?global.KBShell.mount({title:'Semantic review'}):null)
      .then(()=>global.KBContextInspection.mount(host,{operation:'review',validate,render}))
      .catch(()=>{host.textContent='Semantic review unavailable.';});
  });
})(window);
