(() => {
  'use strict';
  const mode = '__MODE__', pollSeconds = __POLL__, requestsPerMinute = __RATE__;
  const $ = id => document.getElementById(id);
  let stop = () => {}, dirty = false, loaded = false, busy = false, activeKind, activeScope, baseline, editEpoch = 0;
  const state = (name, message) => { $('state').dataset.state = name; $('state').textContent = message; };
  const failure = error => state(/restricted/i.test(error.message) ? 'restricted' : /changed since/i.test(error.message) ? 'stale' : 'unavailable', error.message);
  $('theme').onchange = event => {document.documentElement.dataset.theme = event.target.value;};
  $('presentation').onchange = event => {document.documentElement.dataset.presentation = event.target.value;};
  if (!window.brain?.request) {state('unavailable', 'Unavailable: open this app in its configured brain host.'); return;}
  const request = BrainAppHelpers.gate((...args) => window.brain.request(...args), requestsPerMinute);
  function text(tag, value, parent) {const node = document.createElement(tag); node.textContent = value; parent.append(node); return node;}
  async function load(kind, scope) {
    loaded = false; $('write').hidden = true; $('records').replaceChildren(); $('freshness').textContent = '';
    state('loading', 'Loading');
    const observed = await request('revision', {scope});
    const result = await request('records', {kind, limit: 100});
    activeKind = kind; activeScope = scope; baseline = observed;
    $('records').replaceChildren();
    if (mode === 'dashboard') text('p', `${result.total} visible records; ${result.items.length} loaded.`, $('records'));
    else for (const item of result.items) {
      const card = document.createElement('article');
      text('h2', item.title || item.id, card);
      text('p', item.summary || item.markdown || '', card);
      text('p', 'Source: ' + JSON.stringify(item.provenance?.source ?? 'Unavailable'), card);
      text('p', 'Review: ' + JSON.stringify(item.provenance?.review ?? 'Unavailable'), card);
      text('p', 'Revision: ' + JSON.stringify(item.revision ?? 'Unavailable'), card);
      if (mode === 'viewer') text('pre', JSON.stringify(item.values, null, 2), card);
      $('records').append(card);
    }
    loaded = true;
    state(result.items.length ? 'ready' : 'empty', result.items.length ? 'Records loaded' : 'No visible records');
    $('freshness').textContent = 'Loaded ' + new Date().toLocaleString();
  }
  $('query').onsubmit = async event => {
    event.preventDefault(); if (busy) return;
    if (dirty) {state('stale', 'Keep or submit the current form before changing the loaded records.'); return;}
    stop(); busy = true;
    try {
      await load($('kind').value, $('scope').value); $('write').hidden = mode !== 'form';
      stop = BrainAppHelpers.poll({seconds: pollSeconds, initial: baseline,
        read: () => request('revision', {scope: activeScope}),
        changed: () => {state('stale', 'Changed since you opened. Your form is preserved; load records again to refresh.');}, failed: failure});
    } catch (error) {failure(error);} finally {busy = false;}
  };
  $('write').oninput = () => {dirty = true; editEpoch++;};
  let pending;
  $('clear').onclick = () => {
    if (busy || (dirty && !window.confirm('Discard unsaved form edits?'))) return;
    $('record').value = '{}'; $('reason').value = ''; $('evidence').value = '[]';
    pending = undefined; dirty = false; editEpoch++; state('ready', 'Form cleared; shared records are unchanged.');
  };
  $('write').onsubmit = async event => {
    event.preventDefault(); if (!loaded || busy) return;
    busy = true; $('save').disabled = true;
    const submittedEpoch = editEpoch;
    try {
      const body = {expectedRevision: null, record: JSON.parse($('record').value), reason: $('reason').value, evidence: JSON.parse($('evidence').value)};
      const signature = JSON.stringify({kind: activeKind, body});
      if (!pending || pending.signature !== signature) pending = {signature, id: Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('')};
      const result = await request('create', {kind: activeKind, body, idempotencyKey: pending.id});
      pending = undefined; dirty = editEpoch !== submittedEpoch;
      const outcome = result.outcome === 'proposed' ? 'Pending owner review; not yet committed.' : 'Committed.';
      state(result.outcome, outcome + (dirty ? ' Newer form edits remain unsaved.' : ''));
    } catch (error) {failure(error);} finally {busy = false; $('save').disabled = false;}
  };
  window.addEventListener('beforeunload', event => {if (dirty) {event.preventDefault(); event.returnValue = '';}});
  state('empty', 'Choose an enrolled record kind and revision scope to load visible records.');
})();
