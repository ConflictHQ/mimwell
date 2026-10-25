/* Optional schema-bound nested JSON controls. The canonical writer validates all values. */
(function(global){
  'use strict';
  const encoder=new TextEncoder(),object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x),digest=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
  async function sha(value){return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(x=>x.toString(16).padStart(2,'0')).join('');}
  function objectWires(wire){
    if(typeof wire!=='string'||encoder.encode(wire).length>131072||!object(JSON.parse(wire)))throw Error('A bounded JSON correction object is required');
    let nodes=0;const space=i=>{while(/\s/.test(wire[i]||'')&&i<wire.length)i++;return i;};
    function stringEnd(i){for(i++;i<wire.length;i++){if(wire[i]==='\\')i++;else if(wire[i]==='"')return i+1;}throw Error('Invalid JSON text');}
    function end(i,depth=0){
      i=space(i);if(++nodes>16384||depth>64)throw Error('JSON correction structure exceeds bound');
      if(wire[i]==='"')return stringEnd(i);
      if(wire[i]==='{'||wire[i]==='['){const close=wire[i]==='{'?'}':']',isObject=wire[i]==='{';i=space(i+1);
        while(wire[i]!==close){if(isObject){i=space(stringEnd(i));if(wire[i++]!==':')throw Error('Invalid JSON field');}i=space(end(i,depth+1));if(wire[i]===close)break;if(wire[i++]!==',')throw Error('Invalid JSON value');i=space(i);}return i+1;}
      while(i<wire.length&&!/[\s,}\]]/.test(wire[i]))i++;return i;
    }
    const result=Object.create(null);let i=space(0);if(wire[i++]!=='{')throw Error('JSON object required');i=space(i);
    while(wire[i]!=='}'){
      const after=stringEnd(i),name=JSON.parse(wire.slice(i,after));if(Object.hasOwn(result,name)||!name.length||name.length>2000)throw Error('Duplicate or invalid JSON field');i=space(after);if(wire[i++]!==':')throw Error('Invalid JSON field');i=space(i);const afterValue=end(i);result[name]=wire.slice(i,afterValue);i=space(afterValue);if(wire[i]==='}')break;if(wire[i++]!==',')throw Error('Invalid JSON object');i=space(i);
    }
    if(!Object.keys(result).length||Object.keys(result).length>64)throw Error('Select one to 64 changed fields');
    return result;
  }
  function objectWire(wires){return '{\n'+Object.entries(wires).map(([name,wire])=>JSON.stringify(name)+':'+wire).join(',\n')+'\n}';}
  function profile(value,source,binding,index){
    if(value?.format!=='registered-json-record-values/v1'||value.writer!=='json-commit'||value.sourceRevision!==source.revision||value.sourcePath!==source.path||value.selectionSha256!==binding||value.recordIndex!==index||!digest(value.recordSha256)||typeof value.recordWire!=='string'||typeof value.schemaWire!=='string'||!object(value.fields)||!Object.keys(value.fields).length||Object.keys(value.fields).length>64)throw Error('JSON value profile changed');
    for(const row of Object.values(value.fields))if(!object(row)||typeof row.schemaWire!=='string'||typeof row.present!=='boolean'||(row.present?typeof row.valueWire!=='string':row.valueWire!==null))throw Error('Invalid JSON field profile');
    return value;
  }
  function render(value,view,form,controls,changed){
    const label=document.createElement('p');label.textContent='Source: '+value.sourcePath+' · record '+value.recordIndex+' · revision '+value.sourceRevision+'. Edit declared values; nested JSON and integer tokens remain exact. Preview through the canonical schema before proposing.';view.append(label);
    const before=document.createElement('pre');before.textContent=value.recordWire;view.append(before);
    for(const [name,row] of Object.entries(value.fields)){
      const declaration=JSON.parse(row.schemaWire),wrap=document.createElement('label'),input=document.createElement('textarea');wrap.textContent=name;input.rows=object(declaration)&&declaration.type==='string'?2:6;input.maxLength=65536;input.dataset.fileField=name;
      input.dataset.jsonString=String(object(declaration)&&declaration.type==='string');
      input.value=row.present?(input.dataset.jsonString==='true'?JSON.parse(row.valueWire):row.valueWire):'';input.dataset.initialValue=input.value;
      input.addEventListener('input',changed);const details=document.createElement('details'),summary=document.createElement('summary'),schema=document.createElement('pre');summary.textContent='Declared schema';schema.textContent=row.schemaWire;details.append(summary,schema);wrap.append(input,details);form.append(wrap);controls.set(name,input);
    }
  }
  function collect(value,controls,advanced){
    let result;
    if(advanced.trim())result=objectWires(advanced);
    else{result=Object.create(null);for(const [name,input] of controls){if(input.value===input.dataset.initialValue)continue;result[name]=input.dataset.jsonString==='true'?JSON.stringify(input.value):input.value;}}
    let total=0;if(!Object.keys(result).length||Object.keys(result).length>64)throw Error('Enter changed JSON fields');
    for(const [name,wire] of Object.entries(result)){if(!Object.hasOwn(value.fields,name)||typeof wire!=='string'||!wire.trim()||encoder.encode(wire).length>65536)throw Error('Undeclared or excessive JSON field');JSON.parse(wire);total+=encoder.encode(name).length+encoder.encode(wire).length;}
    if(total>131072)throw Error('JSON correction exceeds bound');return result;
  }
  function preview(value,current,wires){
    if(value?.format!=='registered-json-record-values-preview/v1'||value.sourceRevision!==current.sourceRevision||value.sourcePath!==current.sourcePath||value.sourceSchemaSha256!==current.sourceSchemaSha256||value.recordIndex!==current.recordIndex||value.recordSha256!==current.recordSha256||value.beforeRecordWire!==current.recordWire||typeof value.afterRecordWire!=='string'||!digest(value.changesSha256)||value.proposalCreated!==false||value.sourceWritten!==false||value.approval!==null||!object(wires))throw Error('JSON value preview changed');return value;
  }
  global.KBRegisteredJSONValues={sha,objectWires,objectWire,profile,render,collect,preview};
})(typeof window!=='undefined'?window:globalThis);
