(function () {
  'use strict';
  const M = window.KBSensemaking;
  const node = (tag, text, attrs = {}) => {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  };
  const button = (label, action) => {const b = node('button', label, {type:'button'}); b.addEventListener('click', action); return b;};
  async function json(path) {
    const response = await fetch(path, {cache:'no-store'});
    if (!response.ok) throw Error(path + ' unavailable (' + response.status + ').');
    return response.json();
  }
  document.addEventListener('DOMContentLoaded', async () => {
    const host = document.querySelector('[data-kb-sensemaking]'); if (!host) return;
    try {
      await window.KBShell?.mount({title:'Sensemaking'});
      const [contract, config] = await Promise.all([json('/schemas/sensemaking.schema.json'), json('/client.config.json')]);
      const schema = contract.properties.workspaces.items;
      let workspace = M.fresh(schema), original = null, records = [], draft = null, dirty = false, epoch = 0, pendingImport = null;
      let editing = null, form, formDirty = false, activeCollection, sourceDirty = false, activeDiagram = "ontology";
      const status = node('p', 'Unsaved browser draft. Export a workspace file to keep it.', {role:'status','aria-live':'polite'});
      const error = node('pre', '', {role:'alert',class:'sm-error'});
      const actions = node('div', undefined, {class:'sm-actions'});
      const chooser = node('select', undefined, {'aria-label':'Saved workspace'});
      chooser.append(node('option','Select a saved workspace',{value:''}));
      const mainForm = node('div', undefined, {class:'sm-fields'});
      const collection = node('select', undefined, {'aria-label':'Record collection'});
      for (const [key, prop] of Object.entries(schema.properties)) if (prop.type === 'array') collection.append(node('option',prop.title,{value:key}));
      const editor = node('section'), rows = node('section', undefined, {'aria-label':'Current records'});
      const preview = node('section', undefined, {'aria-label':'Diagram preview'});
      const mode = node('select', undefined, {'aria-label':'Diagram view'});
      for (const [value, label] of [['ontology','Concepts'],['sensemaking','Evidence and interpretations'],['cynefin','Cynefin'],['wardley','Wardley map']]) mode.append(node('option',label,{value}));
      const source = node('textarea', undefined, {'aria-label':'Generated Mermaid source',readonly:'',rows:'10'});
      const importSource = button('Import edited diagram as candidate', () => attempt(() => {
        pendingImport = null; apply.disabled = true;
        if (!['cynefin','wardley'].includes(mode.value)) throw Error('Source import is available for Cynefin and Wardley.');
        pendingImport = (mode.value === 'cynefin' ? M.cynefinImport : M.wardleyImport)(source.value, schema);
        apply.disabled = false;
        importReview.textContent = 'Edited diagram is a candidate. Diagram formats omit workspace evidence and context. Export the original workspace JSON before replacing it.';
      }));
      source.addEventListener('input', () => {sourceDirty=true;draft=null;save.disabled=true;epoch++;status.textContent='Edited diagram source is not applied. Import it as a candidate or refresh to discard it.';});
      const diagram = node('div',undefined,{class:'sm-diagram'});
      const diff = node('pre', '', {class:'sm-diff'});
      const reason = node('input', undefined, {'aria-label':'Reason for shared change',placeholder:'Reason for shared change'});
      const evidence = node('textarea', undefined, {'aria-label':'Evidence for shared change',placeholder:'Evidence references, one per line',rows:'2'});
      reason.addEventListener('input', invalidate); evidence.addEventListener('input', invalidate);
      const save = button('Save reviewed change', saveShared); save.disabled = true;
      const stage = button('Preview shared change', stageShared);
      const shared = node('section');
      shared.append(node('h2','Save to this brain'),node('p','The intended-audience field is descriptive. Host policy controls access to the whole workspace artifact. Review the change before saving.'),reason,evidence,stage,save,diff);
      actions.append(button('New workspace', () => {
        if ((dirty || formDirty || sourceDirty) && !confirm('Discard the unsaved draft? Export it first to keep a copy.')) return;
        replace(M.fresh(schema), null); chooser.value = '';
      }),chooser,button('Export workspace JSON', () => attempt(() => {requireApplied();download(M.nativeExport(workspace,schema),workspace.id+'.json','application/json');})));
      host.append(actions,status,error,node('h2','Question and context'),mainForm,node('h2','Records'),collection,editor,rows,node('h2','Views'),preview);
      preview.append(mode,button('Refresh diagram', renderDiagram),diagram,source,importSource,button('Export Mermaid', () => attempt(() => {
        requireApplied();M.assertValid(workspace,schema); download(M.diagram(workspace,mode.value),workspace.id+'.mmd','text/plain');
      })),button('Export OnlineWardleyMaps', () => attempt(() => {
        requireApplied();M.assertValid(workspace,schema); download(M.wardley(workspace,false),workspace.id+'.wardley','text/plain');
      })),button('Export SKOS RDF/XML', () => attempt(() => {
        requireApplied();M.assertValid(workspace,schema); download(M.skosExport(workspace),workspace.id+'.rdf','application/rdf+xml');
      })));
      const imports = node('section');
      const format = node('select',undefined,{'aria-label':'Import format'});
      for (const [value,label] of [['native','Workspace JSON'],['wardley','Wardley / OnlineWardleyMaps subset'],['cynefin','Mermaid Cynefin subset'],['skos','SKOS RDF/XML subset']]) format.append(node('option',label,{value}));
      const file = node('input',undefined,{type:'file','aria-label':'Import file'});
      const importReview = node('p','No import selected.');
      const apply = button('Use imported draft', () => {
        if (!pendingImport) return;
        if ((dirty || formDirty || sourceDirty) && !confirm('Replace this unsaved draft? Export it first to keep a copy.')) return;
        replace(pendingImport,null); pendingImport = null; apply.disabled = true; chooser.value=''; importReview.textContent='Imported as an unsaved draft. No shared record changed.';
      }); apply.disabled = true;
      format.addEventListener('change', () => {pendingImport=null;apply.disabled=true;file.value='';importReview.textContent='Select a file for this format.';});
      file.addEventListener('change', async () => {
        pendingImport=null;apply.disabled=true;
        const selected=file.files[0], selectedFormat=format.value; if (!selected) return;
        try {
          if (selected.size > 1024*1024) throw Error('Import exceeds 1 MiB.');
          const text=await selected.text();
          if (file.files[0]!==selected || format.value!==selectedFormat) return;
          const value=({native:M.nativeImport,wardley:M.wardleyImport,cynefin:M.cynefinImport,skos:M.skosImport})[selectedFormat](text,schema);
          pendingImport=value;apply.disabled=false;error.textContent='';
          importReview.textContent='Ready: '+value.title+'. '+Object.entries(schema.properties).filter(([,p])=>p.type==='array').map(([k,p])=>value[k].length+' '+p.title.toLowerCase()).join(', ')+'. Replaces the browser draft only.';
        } catch(e) {error.textContent=e.message;importReview.textContent='Import refused; current draft unchanged.';}
      });
      imports.append(node('h2','Import and export'),node('p','Workspace JSON preserves all metadata. Diagram and SKOS files carry only the supported map or vocabulary fields; evidence, rationale and review history stay in the workspace JSON. Imports create drafts and grant no permissions.'),format,file,importReview,apply,node('a','Supported formats and limits',{href:'/docs/primitives/sensemaking-workbench.md'}));
      host.append(imports,shared);
      const authority = config.brain?.authority;
      const selected = (config.profile?.overlays || []).some(o=>(typeof o==='string'?o:o.id)==='sensemaking');
      if (!config.features?.authoring || authority || !selected) {
        stage.disabled=true;
        shared.prepend(node('p',authority?'Shared save unavailable here: use the declared authority’s governed knowledge workbench. Export this draft to keep it.':'Shared save unavailable: select the sensemaking overlay and enable the existing file authoring workflow. Export this draft to keep it.'));
        if (authority) shared.append(node('a','Open knowledge workbench',{href:'/knowledge-workbench/'}));
      }
      function attempt(fn) {try {error.textContent='';return fn();} catch(e) {error.textContent=e.message;}}
      function requireApplied() {if(sourceDirty)throw Error('Import edited diagram source as a candidate or refresh it before exporting or saving the workspace.');if(formDirty)throw Error('Apply the current record form or clear it before exporting or saving the workspace.');}
      function invalidate() {draft=null;save.disabled=true;diff.textContent='';epoch++;dirty=true;workspace.updated=new Date().toISOString();status.textContent='Unsaved browser draft. Export a workspace file or preview a shared change to keep it.';}
      function input(key, prop, value, onChange) {
        const wrap=node('label',prop.title || key), types=[].concat(prop.type);
        let control;
        if (prop.enum) {control=node('select');for(const v of prop.enum)control.append(node('option',v,{value:v}));control.value=value;}
        else if (prop.type==='boolean') {control=node('input',undefined,{type:'checkbox'});control.checked=value;}
        else if (types.includes('number')) {control=node('input',undefined,{type:'number',step:'0.01',min:String(prop.minimum ?? 0),max:String(prop.maximum ?? 1)});control.value=value ?? '';}
        else {control=node(prop.type==='array'||['detail','definition','explanation','notes','rationale','boundary','findings'].includes(key)?'textarea':'input');control.value=Array.isArray(value)?value.join('\n'):(value ?? '');}
        control.name=key; if(prop.description)control.title=prop.description;
        control.addEventListener('input',()=>{
          let v=control.value;
          if(prop.type==='boolean')v=control.checked;
          else if(types.includes('number'))v=v===''&&types.includes('null')?null:v===''?NaN:Number(v);
          else if(prop.type==='array')v=v.split('\n').map(s=>s.trim()).filter(Boolean);
          onChange(v);
        });
        wrap.append(control);return wrap;
      }
      function drawMain() {
        mainForm.replaceChildren();
        for(const [key,prop] of Object.entries(schema.properties)) if(prop.type!=='array'&&!['derived','updated'].includes(key)) {
          const field=input(key,prop,workspace[key],v=>{workspace[key]=v;invalidate();});
          if(key==='id'&&original)field.querySelector('input').disabled=true;
          mainForm.append(field);
        }
      }
      function drawEditor(record=null) {
        formDirty=false;activeCollection=collection.value;
        editing=record?.id || null;form=M.clone(record || M.defaults(schema.properties[collection.value].items));
        if(!record)form.id='item-'+M.randomId();
        editor.replaceChildren();
        const fields=node('div',undefined,{class:'sm-fields'});
        for(const [key,prop]of Object.entries(schema.properties[collection.value].items.properties)) {
          const field=input(key,prop,form[key],v=>{form[key]=v;formDirty=true;draft=null;save.disabled=true;epoch++;status.textContent='Record form has unapplied edits. Add or apply the record to include it in the workspace.';});
          if(key==='id'&&editing)field.querySelector('input').disabled=true;
          fields.append(field);
        }
        const add=button(record?'Apply record changes':'Add record',()=>attempt(()=>{
          const next=M.clone(workspace), list=next[collection.value];
          if(editing)list[list.findIndex(r=>r.id===editing)]=M.clone(form);else list.push(M.clone(form));
          M.assertValid(next,schema);workspace=next;invalidate();drawRows();drawEditor();renderDiagram();
        }));
        editor.append(fields,add,button('Clear record form',()=>drawEditor()));
      }
      function drawRows() {
        rows.replaceChildren();const list=workspace[collection.value];
        rows.append(node('p',list.length?list.length+' records.':'No records yet.'));
        for(const r of list) {
          const card=node('article');card.append(node('strong',r.label||r.title||r.id),node('p',r.id));
          card.append(button('Edit '+(r.label||r.title||r.id),()=>{if(formDirty&&!confirm('Discard unapplied record edits?'))return;drawEditor(r);editor.querySelector('input,select,textarea')?.focus();}),button('Remove '+(r.label||r.title||r.id),()=>attempt(()=>{
            if(formDirty&&!confirm('Discard unapplied record edits?'))return;
            const next=M.clone(workspace);next[collection.value]=next[collection.value].filter(x=>x.id!==r.id);
            M.assertValid(next,schema);workspace=next;invalidate();drawRows();drawEditor();renderDiagram();
          })));
          const details=node('details');details.append(node('summary','Record details'),node('pre',JSON.stringify(r,null,2)));card.append(details);rows.append(card);
        }
      }
      function replace(value, baseline) {sourceDirty=false;workspace=M.clone(value);original=baseline?M.clone(baseline):null;invalidate();drawMain();drawRows();drawEditor();renderDiagram();}
      function renderDiagram() {attempt(()=>{
        if(sourceDirty && !confirm('Discard edited diagram source? Import it as a candidate first to keep it.')) {mode.value=activeDiagram;return;}
        sourceDirty=false;activeDiagram=mode.value;
        source.readOnly=!['cynefin','wardley'].includes(mode.value);importSource.disabled=source.readOnly;
        M.assertValid(workspace,schema);
        const text=M.diagram(workspace,mode.value);source.value=text;diagram.replaceChildren();
        if(!text || (mode.value==='wardley'&&!workspace.components.length) || (mode.value==='cynefin'&&!workspace.assessments.length)) {diagram.append(node('p','Add records to preview this view.'));return;}
        if(!window.mermaid) {diagram.append(node('p','Diagram renderer unavailable. Your records and source remain available.'));return;}
        const pre=node('pre'),code=node('code',text,{class:'language-mermaid'});pre.append(code);diagram.append(pre);window.KBRender.renderMermaid(diagram);
      });}
      async function stageShared() {
        try {
          error.textContent='';requireApplied();M.assertValid(workspace,schema);
          const api=window.__kbEditorApi;if(!api)throw Error('Existing authoring service is unavailable. Export the draft to keep it.');
          const observed=epoch, submitted=M.clone(workspace);
          const result=await api.stageEdit('sensemaking',original,submitted,{reason:reason.value.trim(),evidence:evidence.value.split('\n').map(s=>s.trim()).filter(Boolean)});
          if(epoch!==observed)throw Error('Draft changed while preparing the preview. Preview again.');
          const file=result.files?.find(f=>f.path==='app/sensemaking.json');
          if(!file)throw Error('Authoring returned no inspectable source change.');
          const before=JSON.parse(file.before).workspaces.find(w=>w.id===submitted.id) || null;
          if(JSON.stringify(before)!==JSON.stringify(original))throw Error('Workspace changed upstream. Export your draft and reload before reconciling.');
          draft={result,submitted,epoch:observed};diff.textContent=file.path+'\nBEFORE\n'+file.before+'\nAFTER\n'+file.after;save.disabled=false;status.textContent='Review the source diff, then save. No shared change has been committed.';
        }catch(e){draft=null;save.disabled=true;error.textContent=e.message;}
      }
      async function saveShared() {
        if(!draft||draft.epoch!==epoch)return;
        const selectedDraft=draft;save.disabled=true;draft=null;
        try {
          const response=await window.__kbEditorApi.commit(config.authoring?.governance?selectedDraft.result:selectedDraft.result.files,'Update sensemaking workspace');
          if(epoch!==selectedDraft.epoch){status.textContent='The reviewed version was submitted; newer browser edits remain unsaved.';return;}
          if(response.pullRequest) {status.textContent='Change submitted for review. It is not yet the published workspace.';}
          else {original=M.clone(selectedDraft.submitted);dirty=false;status.textContent='Source change saved. The portal updates after its normal rebuild and deployment.';}
        }catch(e){error.textContent=e.message;status.textContent='Save failed. Draft retained; reconcile and preview again.';}
      }
      function download(text,name,type) {const url=URL.createObjectURL(new Blob([text],{type}));const link=node('a','',{href:url,download:name});link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);}
      collection.addEventListener('change',()=>{if(formDirty&&!confirm('Discard unapplied record edits?')){collection.value=activeCollection;return;}drawRows();drawEditor();});mode.addEventListener('change',renderDiagram);
      chooser.addEventListener('change',()=>{
        const selectedRecord=records.find(w=>w.id===chooser.value);if(!selectedRecord)return;
        if((dirty||formDirty||sourceDirty)&&!confirm('Discard the unsaved draft? Export it first to keep a copy.')){chooser.value=original?.id||'';return;}
        replace(selectedRecord,selectedRecord);dirty=false;status.textContent='Loaded published workspace. Changes remain drafts until saved.';
      });
      window.addEventListener('beforeunload',event=>{if(dirty||formDirty||sourceDirty){event.preventDefault();event.returnValue='';}});
      drawMain();drawRows();drawEditor();renderDiagram();
      try {
        const data=await json('/app/sensemaking.json');
        if(!Array.isArray(data.workspaces))throw Error('Invalid workspace collection.');
        for(const r of data.workspaces)M.assertValid(r,schema);
        records=data.workspaces;for(const r of records)chooser.append(node('option',r.title,{value:r.id}));
      }catch(e){status.textContent='Published workspaces unavailable. Browser drafts still work; shared-save requests remain subject to host validation.';error.textContent=e.message;}
    }catch(e){host.replaceChildren(node('p','Sensemaking unavailable: '+e.message,{role:'alert'}));}
  });
})();
