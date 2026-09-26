/* Fixture brain tests: no network or production credentials. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {gate, poll} = require('./poll.js');
(async () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, 'app.json')));
  const fixture = {items: [{id:'fixture-1', title:'Fixture record', provenance:{source:'fixture', review:'accepted'}}], total:1};
  let requests = 0, now = 0;
  const request = gate(async operation => {requests++; assert.equal(operation, 'records'); return fixture;}, 1, () => now);
  assert.equal((await request('records')).items[0].provenance.source, 'fixture');
  await assert.rejects(request('records'), /budget/); assert.equal(requests, 1);
  now = 60001; await request('records'); assert.equal(requests, 2);
  let next, delay, revision = 1, changes = 0, failures = 0;
  const stop = poll({seconds: manifest.pollSeconds, read: async () => revision,
    changed: () => {changes++;}, failed: () => {failures++;}, schedule: (fn, ms) => {next = fn; delay = ms;}, cancel: () => {next = undefined;}});
  await next(); revision++; await next(); assert.equal(changes, 1); assert.equal(failures, 0);
  assert.equal(delay, manifest.pollSeconds * 1000); stop(); assert.equal(next, undefined);
  for (const file of [manifest.entry, 'app.js', 'shell.css']) assert.ok(fs.statSync(path.join(__dirname, file)).size);
  console.log('OK: fixture reads, request budget, revision change, cancellation and bundle assets');
})().catch(error => {console.error(error); process.exitCode = 1;});

/* Execute the generated app, including its explicit-submit path. */
(async () => {
  const vm = require('node:vm');
  class Element {
    constructor() {this.value = ''; this.dataset = {}; this.children = []; this.hidden = false; this.textContent = '';}
    append(node) {this.children.push(node);}
    replaceChildren() {this.children = [];}
  }
  const elements = new Map();
  const get = id => {if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id);};
  const calls = [];
  let denied = false, releaseWrite, holdWrite = false;
  const sandbox = {
    document: {getElementById: get, createElement: () => new Element(), documentElement: new Element()},
    window: {confirm: () => true, addEventListener() {}, brain: {async request(operation, args) {
      calls.push({operation, args});
      if (denied) throw new Error('Restricted');
      if (operation === 'records') return {total:1, items:[{id:'one', title:'<img src=x onerror=bad()>', provenance:{source:'fixture', review:'accepted'}, values:{title:'Fixture'}}]};
      if (operation === 'create') {if (holdWrite) await new Promise(resolve => {releaseWrite = resolve;}); assert.equal(args.body.expectedRevision, null); assert.ok(args.idempotencyKey); return {outcome:'proposed'};}
      return 'fixture-revision';
    }}},
    BrainAppHelpers: {gate, poll: () => () => {}},
    crypto: require('node:crypto').webcrypto, Date, JSON, Array, Error
  };
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), sandbox);
  get('kind').value = 'fixture-kind'; get('scope').value = 'fixture-kind';
  await get('query').onsubmit({preventDefault() {}});
  assert.equal(get('state').dataset.state, 'ready');
  assert.equal(calls[0].operation, 'revision');
  assert.equal(calls[1].operation, 'records');
  if (!get('write').hidden) {
    get('record').value = '{"id":"fixture:new"}'; get('evidence').value = '["fixture:source"]'; get('reason').value = 'Fixture observation';
    get('write').oninput(); assert.equal(calls.length, 2, 'typing never writes');
    await get('write').onsubmit({preventDefault() {}});
    assert.equal(get('state').textContent, 'Pending owner review; not yet committed.');
    holdWrite = true; get('write').oninput();
    const saving = get('write').onsubmit({preventDefault() {}});
    await new Promise(resolve => setImmediate(resolve));
    get('record').value = '{"id":"fixture:newer"}'; get('write').oninput(); releaseWrite(); await saving; holdWrite = false;
    assert.match(get('state').textContent, /Newer form edits remain unsaved/);
    get('record').value = '{"id":"fixture:new"}';
    denied = true; get('write').oninput();
    await get('write').onsubmit({preventDefault() {}});
    assert.equal(get('state').dataset.state, 'restricted');
    assert.equal(get('record').value, '{"id":"fixture:new"}');
    get('clear').onclick(); assert.equal(get('record').value, '{}');
  }
  denied = true;
  // A fresh document has no unsaved form preventing the replacement query.
  vm.runInNewContext(fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8'), sandbox);
  await get('query').onsubmit({preventDefault() {}});
  assert.equal(get('state').dataset.state, 'restricted');
  assert.equal(get('records').children.length, 0); assert.equal(get('write').hidden, true);
  console.log('OK: generated app fixture read, explicit proposal, denied draft preservation and failed-query reset');
})().catch(error => {console.error(error); process.exitCode = 1;});

(async () => {
  let next, release, changes = 0, failures = 0;
  const stop = poll({seconds:30, initial:'before', read:() => new Promise(resolve => {release=resolve;}),
    changed:() => {changes++;}, failed:() => {failures++;}, schedule:fn => {next=fn;}, cancel:() => {}});
  const waiting = next(); stop(); release('after'); await waiting;
  assert.equal(changes,0); assert.equal(failures,0);
  let observed=0;
  const end = poll({seconds:30, initial:'before', read:async () => 'after', changed:() => {observed++;},
    failed:() => {}, schedule:fn => {next=fn;}, cancel:() => {}});
  await next(); end(); assert.equal(observed,1);
  console.log('OK: canceled in-flight poll is inert; initial revision detects first-interval changes');
})().catch(error => {console.error(error); process.exitCode=1;});
