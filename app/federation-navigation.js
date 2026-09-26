/* Optional policy-filtered navigation. No static graph fallback or credentials. */
(function (global) {
  'use strict';
  const defaults = {maxParticipants:64,maxLinks:256,maxDepth:8,maxPaths:8,maxExpansions:512,maxBytes:262144};
  const identity = value => typeof value === 'string' && value.trim() && value.length <= 200;
  const node = (tag, text, cls) => {
    const item = document.createElement(tag);
    if (text != null) item.textContent = text;
    if (cls) item.className = cls;
    return item;
  };

  function mount(host, settings) {
    host.replaceChildren();
    if (!settings || settings.protocolVersion !== '1.0' || !Array.isArray(settings.roots) ||
        !settings.roots.length || settings.roots.length > 32 || !settings.roots.every(identity) ||
        new Set(settings.roots).size !== settings.roots.length) {
      host.append(node('p', 'Navigation configuration unavailable.', 'ks-state'));
      return;
    }
    const initialRoots = [...settings.roots];
    let roots = [...initialRoots], sequence = 0, controller;
    let names = new Map();
    const easy = () => global.KBEasyView && global.KBEasyView.current() === 'easy';
    const toolbar = node('div', null, 'fn-toolbar');
    const reload = node('button', 'Refresh'), reset = node('button', 'Start');
    reload.type = reset.type = 'button';
    toolbar.append(reset, reload);
    const status = node('p');
    status.setAttribute('role', 'status');
    const content = node('div', null, 'fn-content');
    host.append(toolbar, status, content);

    function focusFromLocation() {
      const value = new URLSearchParams(global.location.hash.slice(1)).get('participant');
      return identity(value) ? value : null;
    }
    function link(id) {
      const a = node('a', easy() ? names.get(id) || 'Connected brain' : id);
      a.href = '#participant=' + encodeURIComponent(id);
      a.dataset.participant = id;
      return a;
    }
    function render(result) {
      const graph = result.graph;
      if (result.protocolVersion !== '1.0' || !graph || !Array.isArray(graph.participants) ||
          !Array.isArray(graph.links) || !Array.isArray(graph.truncation) || !Array.isArray(result.paths) ||
          !Array.isArray(result.truncation) || !Array.isArray(result.cycleLinks) || !result.focus ||
          !graph.authorization || !Array.isArray(graph.unavailable)) throw new Error('Invalid navigation');
      names = new Map(graph.participants.map((p, i) => [p.id, p.name || 'Connected brain ' + (i + 1)]));
      const ids = new Set(graph.participants.map(p => p.id));
      if (ids.size !== graph.participants.length || ![...ids].every(identity) ||
          graph.links.some(e => !ids.has(e.source) || !ids.has(e.target) || !['owned_by','member','peer'].includes(e.relation)) ||
          result.paths.some(p => !Array.isArray(p.participants) || p.participants.some(id => !ids.has(id)) ||
            !Array.isArray(p.relations) || p.relations.length !== p.participants.length - 1 ||
            p.relations.some(relation => !['owned_by','member','peer'].includes(relation)))) throw new Error('Invalid graph');
      const partial = [...new Set([...graph.truncation, ...result.truncation])];
      status.textContent = graph.participants.length + ' visible brains · ' + graph.links.length + ' relationships' +
        (partial.length ? ' · Partial result (' + partial.join(', ') + ')' : '');
      const scope = node('p', (easy() ? 'Showing connections from: ' : 'Visible roots: ') + (roots.filter(id => ids.has(id)).map(id => easy() ? names.get(id) : id).join(', ') || 'none'), 'ks-note');
      const list = node('section', null, 'ks-card');
      list.setAttribute('aria-label', 'Visible brains');
      list.append(node('h2', 'Visible brains'));
      const ul = node('ul');
      for (const participant of graph.participants) {
        const li = node('li'); li.append(link(participant.id)); ul.append(li);
      }
      list.append(ul);
      const detail = node('section', null, 'ks-card');
      detail.setAttribute('aria-label', 'Brain identity and paths');
      const selected = graph.participants.find(p => p.id === result.focus.participant);
      if (selected) {
        if (easy()) {
          detail.append(node('h2', names.get(selected.id)), node('p', 'Selected brain. Information shown here belongs to its source; changes require that brain’s permission.'));
          const deeper = node('button', 'Go deeper in Advanced view'); deeper.type = 'button';
          deeper.onclick = () => global.KBEasyView.setMode('advanced', true); detail.append(deeper);
        }
        const exact = node('section'); exact.setAttribute('data-kb-advanced',''); detail.append(exact);
        exact.append(node('h2', selected.id), node('h3', 'Source identity'));
        exact.append(node('p', 'Manifest: ' + selected.manifest.identity), node('p', 'Manifest SHA-256: ' + selected.manifest.sha256, 'fn-coordinate'));
        for (const realm of selected.realms) {
          exact.append(node('p', realm.realm + ' · ' + realm.authority + ' · ' + realm.store + ' · ' + realm.transport, 'fn-coordinate'),
            node('p', 'Revision: ' + realm.revision, 'fn-coordinate'));
        }
        const explore = node('button', 'Explore from ' + (easy() ? names.get(selected.id) : selected.id));
        explore.type = 'button';
        explore.onclick = () => { roots = [selected.id]; load(); };
        detail.append(explore);
        exact.append(node('h3', 'Paths from these roots'));
        if (!result.paths.length) exact.append(node('p', 'No path returned within the current limits.'));
        for (const path of result.paths) {
          const row = node('p', null, 'fn-path');
          path.participants.forEach((id, index) => {
            if (index) row.append(document.createTextNode(' — ' + path.relations[index - 1] + ' → '));
            row.append(link(id));
          });
          exact.append(row);
        }
        exact.append(node('h3', 'Relationships'));
        for (const edge of graph.links.filter(e => e.source === selected.id || e.target === selected.id)) {
          const row = node('p');
          row.append(link(edge.source), document.createTextNode(' — ' + edge.relation + ' → '), link(edge.target));
          exact.append(row);
        }
      } else detail.append(node('p', result.focus.state === 'none' ? 'Choose a brain to inspect its identity and paths.' : 'Brain unavailable in this view.'));
      const fragment = document.createDocumentFragment();
      fragment.append(scope, list, detail);
      if (result.cycleLinks.length) fragment.append(node('p', 'Cycle closures encountered during path search: ' + result.cycleLinks.length + '. Paths never repeat a brain.', 'ks-note'));
      if (graph.unavailable.length) fragment.append(node('p', 'Some requested roots are unavailable.', 'ks-note'));
      fragment.append(node('p', 'Membership, ownership and peer relationships are distinct. These results do not grant record access.', 'ks-note'));
      content.replaceChildren(fragment);
    }
    async function load() {
      const current = ++sequence;
      if (controller) controller.abort();
      controller = new AbortController();
      const signal = controller.signal;
      const timeout = setTimeout(() => { if (current === sequence) controller.abort(); }, 12000);
      content.replaceChildren();
      status.textContent = 'Loading visible brains…';
      host.setAttribute('aria-busy', 'true');
      try {
        const response = await fetch('/brain-navigation', {method:'POST', credentials:'same-origin',
          cache:'no-store', redirect:'error', signal, headers:{'content-type':'application/json'},
          body:JSON.stringify({protocolVersion:'1.0',roots,focus:focusFromLocation(),budget:{...defaults,...settings.budget,...(easy()?{maxDepth:1}:{})}})});
        if (!response.ok) throw new Error('Unavailable');
        const result = await response.json();
        if (current !== sequence) return;
        render(result);
      } catch {
        if (current !== sequence) return;
        content.replaceChildren();
        status.textContent = 'Navigation unavailable. Refresh to try again.';
      } finally {
        clearTimeout(timeout);
        if (current === sequence) host.removeAttribute('aria-busy');
      }
    }
    reload.onclick = load;
    reset.onclick = () => { roots = [...initialRoots]; load(); };
    global.addEventListener('hashchange', load);
    global.addEventListener('kb-view-change', load);
    load();
  }
  global.KBFederationNavigation = {mount};
})(window);
