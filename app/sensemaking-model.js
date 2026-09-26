/* Portable workbench records and deliberately bounded interchange. No network or writes. */
(function (global) {
  'use strict';
  const clone = value => JSON.parse(JSON.stringify(value));
  const MAX_BYTES = 1024 * 1024;
  const nativeDocument = value => JSON.stringify({format: 'brain-sensemaking/v1', workspace: value}, null, 2) + '\n';
  const randomId = () => Array.from(global.crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('');
  function bounded(text) {
    if (typeof text !== 'string' || new TextEncoder().encode(text).length > MAX_BYTES) throw Error('Import exceeds 1 MiB.');
    return text;
  }
  function defaults(schema) {
    if (schema.enum) return schema.enum[0];
    if (Array.isArray(schema.type) && schema.type.includes('null')) return null;
    if (schema.type === 'array') return [];
    if (schema.type === 'object') return Object.fromEntries(Object.entries(schema.properties).filter(([k]) => k !== 'derived').map(([k, s]) => [k, defaults(s)]));
    return schema.type === 'boolean' ? false : schema.type === 'number' ? 0.5 : '';
  }
  function fresh(schema) {
    const value = defaults(schema);
    value.id = 'workspace-' + randomId();
    value.title = 'Untitled workspace';
    value.updated = new Date().toISOString();
    return value;
  }
  function check(value, schema, path = 'workspace') {
    const errors = [], types = [].concat(schema.type || []);
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : typeof value;
    if (types.length && !types.includes(actual) && !(types.includes('integer') && Number.isInteger(value))) return [path + ': wrong type'];
    if (schema.enum && !schema.enum.includes(value)) errors.push(path + ': unsupported value');
    if (typeof value === 'number' && (!Number.isFinite(value) || value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity))) errors.push(path + ': out of range');
    if (typeof value === 'string' && (value.length < (schema.minLength || 0) || value.length > (schema.maxLength || Infinity) || (schema.pattern && !new RegExp(schema.pattern).test(value)))) errors.push(path + ': invalid text');
    if (Array.isArray(value)) {
      if (value.length > (schema.maxItems || Infinity)) errors.push(path + ': too many rows');
      if (schema.uniqueItems && new Set(value.map(v => JSON.stringify(v))).size !== value.length) errors.push(path + ': duplicates');
      value.forEach((v, i) => errors.push(...check(v, schema.items, path + '[' + i + ']')));
    } else if (value && typeof value === 'object') {
      for (const k of schema.required || []) if (!Object.hasOwn(value, k)) errors.push(path + ': missing ' + k);
      for (const k of Object.keys(value)) {
        if (!schema.properties?.[k]) { if (schema.additionalProperties === false) errors.push(path + ': unknown ' + k); }
        else errors.push(...check(value[k], schema.properties[k], path + '.' + k));
      }
    }
    return errors;
  }
  function validate(value, schema) {
    const errors = check(value, schema);
    if (errors.length) return errors;
    if (new TextEncoder().encode(nativeDocument(value)).length > MAX_BYTES) errors.push('Workspace export exceeds 1 MiB.');
    for (const [key, prop] of Object.entries(schema.properties)) {
      if (prop.type !== 'array') continue;
      if (new Set(value[key].map(r => r.id)).size !== value[key].length) errors.push(key + ': duplicate IDs');
    }
    const has = (key, id) => value[key].some(r => r.id === id);
    for (const [key, target] of [['relations', 'concepts'], ['dependencies', 'components']]) for (const row of value[key]) {
      if (!has(target, row.from) || !has(target, row.to)) errors.push(key + ': unresolved endpoints for ' + row.id);
      if (row.from === row.to) errors.push(key + ': self-reference for ' + row.id);
    }
    for (const row of value.interpretations) for (const id of row.observations) if (!has('observations', id)) errors.push('interpretations: unknown observation ' + id);
    for (const row of value.probes) if (!has('assessments', row.assessment)) errors.push('probes: unknown assessment ' + row.assessment);
    if (new Set(value.components.map(c => c.label)).size !== value.components.length) errors.push('Wardley component names must be unique.');
    const uris = value.concepts.map(c => c.uri).filter(Boolean);
    if (new Set(uris).size !== uris.length) errors.push('Concept URIs must be unique.');
    for (const uri of uris) if (!/^(https?:\/\/|urn:)[^\s<>"{}|\\^`]+$/.test(uri)) errors.push('Concept URI must be an absolute HTTP(S) URI or URN.');
    return errors;
  }
  function assertValid(value, schema) {
    const errors = validate(value, schema);
    if (errors.length) throw Error(errors.join('\n'));
    return value;
  }
  function nativeImport(text, schema) {
    const doc = JSON.parse(bounded(text));
    if (doc.format !== 'brain-sensemaking/v1' || Object.keys(doc).some(k => !['format', 'workspace'].includes(k))) throw Error('Unsupported workspace envelope.');
    assertValid(doc.workspace, schema);
    return assertValid({...defaults(schema), ...doc.workspace}, schema);
  }
  const nativeExport = (value, schema) => nativeDocument(assertValid(value, schema));
  const label = value => String(value).replace(/[&<>"\n\r\[\]{}|`]/g, c => '&#' + c.charCodeAt(0) + ';');
  function wardley(value, header = true) {
    const lines = header ? ['wardley-beta'] : [];
    lines.push('title ' + value.title.replace(/[\r\n]/g, ' '));
    const names = Object.fromEntries(value.components.map(c => [c.id, c.label]));
    for (const c of value.components) {
      lines.push(c.role + ' ' + c.label + ' [' + c.visibility + ', ' + c.evolution + ']' + (c.sourcing !== 'none' ? ' (' + c.sourcing + ')' : '') + (c.inertia ? ' (inertia)' : ''));
      if (c.targetEvolution !== null) lines.push('evolve ' + c.label + ' ' + c.targetEvolution);
    }
    for (const d of value.dependencies) lines.push(names[d.from] + ' -> ' + names[d.to]);
    return lines.join('\n') + '\n';
  }
  function diagram(value, mode) {
    if (mode === 'wardley') return wardley(value);
    if (mode === 'cynefin') {
      const lines = ['cynefin-beta'];
      for (const domain of ['complex', 'complicated', 'clear', 'chaotic', 'confusion']) {
        lines.push(domain);
        for (const a of value.assessments.filter(a => a.domain === domain)) lines.push('  "' + label(a.title) + '"');
      }
      return lines.join('\n') + '\n';
    }
    const lines = ['flowchart TD'];
    if (mode === 'ontology') {
      for (const c of value.concepts) lines.push('n_' + c.id.replaceAll('-', '_') + '["' + label(c.label) + '"]');
      for (const r of value.relations) lines.push('n_' + r.from.replaceAll('-', '_') + ' -->|' + r.relation + '| n_' + r.to.replaceAll('-', '_'));
    } else {
      for (const o of value.observations) lines.push('o_' + o.id.replaceAll('-', '_') + '["' + label(o.title) + '"]');
      for (const i of value.interpretations) {
        lines.push('i_' + i.id.replaceAll('-', '_') + '["' + label(i.title) + '"]');
        for (const id of i.observations) lines.push('o_' + id.replaceAll('-', '_') + ' --> i_' + i.id.replaceAll('-', '_'));
      }
    }
    return lines.length > 1 ? lines.join('\n') + '\n' : '';
  }
  function wardleyImport(text, schema) {
    const result = fresh(schema), pending = [], evolution = [];
    const name = '[A-Za-z][A-Za-z0-9 ._-]{0,99}', num = '(0(?:\\.\\d+)?|1(?:\\.0+)?)';
    let lineNo = 0, titleSeen = false;
    for (const raw of bounded(text).split(/\r?\n/)) {
      lineNo++;
      const line = raw.trim();
      if (!line || line.startsWith('//') || line.startsWith('%%') || (line === 'wardley-beta' && lineNo === 1)) continue;
      let m;
      if ((m = /^title (.+)$/.exec(line))) {
        if (titleSeen) throw Error('Duplicate title.');
        result.title = m[1]; titleSeen = true;
      } else if ((m = new RegExp('^(anchor|component) (' + name + ') \\[' + num + ',\\s*' + num + '\\]((?: \\((?:build|buy|outsource|market|inertia)\\))*)$').exec(line))) {
        const c = defaults(schema.properties.components.items);
        Object.assign(c, {id: 'component-' + (result.components.length + 1), label: m[2].trim(), role: m[1], visibility: Number(m[3]), evolution: Number(m[4])});
        const decorators = Array.from(m[5].matchAll(/\(([^)]+)\)/g), v => v[1]);
        const strategies = decorators.filter(v => v !== 'inertia');
        if (strategies.length > 1 || new Set(decorators).size !== decorators.length) throw Error('Ambiguous decorators on line ' + lineNo);
        c.sourcing = strategies[0] || 'none'; c.inertia = decorators.includes('inertia');
        result.components.push(c);
      } else if ((m = new RegExp('^evolve (' + name + ') ' + num + '$').exec(line))) evolution.push([m[1].trim(), Number(m[2])]);
      else if ((m = new RegExp('^(' + name + ') -> (' + name + ')$').exec(line))) pending.push([m[1].trim(), m[2].trim()]);
      else throw Error('Unsupported Wardley syntax on line ' + lineNo + '. Import left unchanged.');
    }
    if (!result.components.length) throw Error('No Wardley components found.');
    const resolve = name => {const c = result.components.find(c => c.label === name); if (!c) throw Error('Unknown component: ' + name); return c;};
    for (const [name, target] of evolution) {const c = resolve(name); if (c.targetEvolution !== null) throw Error('Duplicate evolution.'); c.targetEvolution = target;}
    for (const [from, to] of pending) result.dependencies.push({id: 'dependency-' + (result.dependencies.length + 1), from: resolve(from).id, to: resolve(to).id, rationale: ''});
    return assertValid(result, schema);
  }
  function cynefinImport(text, schema) {
    const result = fresh(schema); let domain = null, first = true;
    for (const raw of bounded(text).split(/\r?\n/)) {
      const line = raw.trim(); if (!line) continue;
      if (first) {first = false; if (line !== 'cynefin-beta') throw Error('Expected cynefin-beta.'); continue;}
      if (['complex','complicated','clear','chaotic','confusion'].includes(line)) {domain = line; continue;}
      const m = /^"([^"<>]*)"$/.exec(line);
      if (!m || !domain) throw Error('Unsupported Cynefin syntax: use domain blocks and quoted labels.');
      const a = defaults(schema.properties.assessments.items);
      Object.assign(a, {id: 'assessment-' + (result.assessments.length + 1), domain, title: m[1].replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)))});
      result.assessments.push(a);
    }
    if (first) throw Error('Empty Cynefin document.');
    return assertValid(result, schema);
  }
  const xml = s => String(s).replace(/[<>&"']/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&apos;'}[c]));
  function skosExport(value) {
    const uri = c => c.uri || 'urn:brain:sensemaking:' + value.id + ':' + c.id;
    const byId = Object.fromEntries(value.concepts.map(c => [c.id, c]));
    return '<?xml version="1.0" encoding="UTF-8"?>\n<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:skos="http://www.w3.org/2004/02/skos/core#">\n' + value.concepts.map(c =>
      '<skos:Concept rdf:about="' + xml(uri(c)) + '"><skos:prefLabel>' + xml(c.label) + '</skos:prefLabel><skos:definition>' + xml(c.definition) + '</skos:definition><skos:scopeNote>' + xml(c.context) + '</skos:scopeNote>' + value.relations.filter(r => r.from === c.id).map(r => '<skos:' + r.relation + ' rdf:resource="' + xml(uri(byId[r.to])) + '"/>').join('') + '</skos:Concept>').join('\n') + '\n</rdf:RDF>\n';
  }
  function skosImport(text, schema, Parser = global.DOMParser) {
    bounded(text);
    if (/<!DOCTYPE|<!ENTITY/i.test(text)) throw Error('DTD/entity declarations are unsupported.');
    const doc = new Parser().parseFromString(text, 'application/xml');
    if (doc.querySelector('parsererror')) throw Error('Invalid RDF/XML.');
    const RDF = 'http://www.w3.org/1999/02/22-rdf-syntax-ns#', SKOS = 'http://www.w3.org/2004/02/skos/core#';
    const root = doc.documentElement, result = fresh(schema), pending = [];
    if (root.namespaceURI !== RDF || root.localName !== 'RDF') throw Error('Expected rdf:RDF.');
    if ([...root.attributes].some(a => a.namespaceURI !== 'http://www.w3.org/2000/xmlns/')) throw Error('RDF root attributes such as xml:base or xml:lang need a richer adapter.');
    for (const node of root.children) {
      if (node.namespaceURI !== SKOS || node.localName !== 'Concept') throw Error('Only explicit skos:Concept records are supported.');
      const c = defaults(schema.properties.concepts.items), seen = new Set();
      c.id = 'concept-' + (result.concepts.length + 1); c.uri = node.getAttributeNS(RDF, 'about') || '';
      if (!c.uri) throw Error('Every concept needs an absolute rdf:about URI.');
      for (const child of node.children) {
        if (child.namespaceURI !== SKOS || child.children.length) throw Error('Unsupported nested RDF or namespace.');
        const fields = {prefLabel:'label', definition:'definition', scopeNote:'context'};
        if (fields[child.localName]) {
          if (child.attributes.length || seen.has(child.localName)) throw Error('Language tags, attributes and repeated labels require a richer SKOS adapter.');
          c[fields[child.localName]] = child.textContent; seen.add(child.localName);
        } else if (['broader','related','closeMatch','exactMatch'].includes(child.localName)) {
          const target = child.getAttributeNS(RDF, 'resource');
          if (!target || child.attributes.length !== 1 || child.textContent.trim()) throw Error('Expected one rdf:resource relation.');
          pending.push({from:c.id, target, relation:child.localName});
        } else throw Error('Unsupported SKOS property: ' + child.localName);
      }
      // Reject unhandled attributes rather than silently discard source semantics.
      if ([...node.attributes].some(a => !(a.namespaceURI === RDF && a.localName === 'about'))) throw Error('Unsupported concept attributes.');
      result.concepts.push(c);
    }
    for (const p of pending) {
      const target = result.concepts.find(c => c.uri === p.target);
      if (!target) throw Error('External SKOS relationship target is not included.');
      result.relations.push({id:'relation-' + (result.relations.length + 1), from:p.from, to:target.id, relation:p.relation, rationale:'', source:''});
    }
    if (!result.concepts.length) throw Error('No concepts found.');
    return assertValid(result, schema);
  }
  const api = {clone, randomId, defaults, fresh, validate, assertValid, nativeImport, nativeExport, diagram, wardley, wardleyImport, cynefinImport, skosExport, skosImport};
  if (typeof module !== 'undefined') module.exports = api;
  else global.KBSensemaking = api;
})(typeof window === 'undefined' ? globalThis : window);
