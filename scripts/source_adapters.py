"""Opt-in projections of authored documents, wiki mirrors and tracker snapshots.

No fetches or source writes. Configuration selects adapters; ontology mappings
must agree. Exclusions apply before source reads; selected invalid input fails.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
from pathlib import Path
import re

from tracker_refresh import strict

KINDS = {'docs': ('doc', 'Doc'), 'wiki': ('wiki-page', 'WikiPage'), 'issues': ('issue', 'Issue'),
         'activity': ('activity-event', 'ActivityEvent')}


def _json(path):
    def pairs(items):
        out = {}
        for key, value in items:
            if key in out:
                raise ValueError('source adapters: duplicate JSON key')
            out[key] = value
        return out

    def constant(_):
        raise ValueError('source adapters: nonfinite JSON')

    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=pairs, parse_constant=constant)


def _path(root, relative):
    if not isinstance(relative, str) or not relative or '\\' in relative:
        raise ValueError('source adapters: expected a relative POSIX path')
    part = Path(relative)
    if part.is_absolute() or '..' in part.parts or part.as_posix() != relative or relative == '.':
        raise ValueError('source adapters: source must be inside the brain')
    for i in range(1, len(part.parts) + 1):
        if (root / Path(*part.parts[:i])).is_symlink():
            raise ValueError('source adapters: symlink sources are unsupported')
    return root / part


def _strings(value, field):
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ValueError(f'source adapters: {field} must be an array of strings')
    return value


def _included(relative, knowledge):
    skip = _strings(knowledge.get('skipNames', []), 'skipNames')
    excluded = _strings(knowledge.get('excludeFromBrain', []), 'excludeFromBrain')
    return (Path(relative).name.lower() not in {s.lower() for s in skip}
            and not any(fnmatch.fnmatchcase(relative, pattern) for pattern in excluded))


def _directories(root, knowledge, adapter):
    sources = knowledge.get('sources', [])
    if not isinstance(sources, list):
        raise ValueError('source adapters: knowledge.sources must be an array')
    declared = []
    for source in sources:
        if not isinstance(source, dict):
            raise ValueError('source adapters: invalid knowledge source')
        relative = source.get('path')
        if isinstance(relative, str) and relative.rstrip('/').split('/')[-1] == adapter:
            recursive = source.get('recursive', adapter == 'docs')
            if not isinstance(recursive, bool):
                raise ValueError('source adapters: recursive must be boolean')
            declared.append((relative, recursive))
    return declared or [(f'knowledge/{adapter}', adapter == 'docs')]


def _markdown(root, knowledge, adapter, frontmatter, first_prose):
    paths = set()
    for relative, recursive in _directories(root, knowledge, adapter):
        directory = _path(root, relative)
        if not _included(relative, knowledge):
            continue
        if not directory.exists():
            if strict():
                raise ValueError('source adapters: selected markdown input unavailable')
            continue
        if not directory.is_dir():
            raise ValueError('source adapters: markdown source must be a directory')
        def onerror(error):
            if strict():
                raise error

        for current, dirs, files in os.walk(directory, followlinks=False, onerror=onerror):
            retained = []
            for name in sorted(dirs):
                rel = (Path(current) / name).relative_to(root).as_posix()
                if _included(rel, knowledge):
                    _path(root, rel)
                    retained.append(name)
            dirs[:] = retained if recursive else []
            for name in sorted(files):
                rel = (Path(current) / name).relative_to(root).as_posix()
                if name.lower().endswith('.md') and _included(rel, knowledge):
                    _path(root, rel)
                    paths.add(rel)
    nodes = []
    for rel in sorted(paths):
        raw = _path(root, rel).read_text(encoding='utf-8', errors='replace')
        fields, body = frontmatter(raw)
        heading = re.search(r'^#\s+(.+)$', body, re.MULTILINE)
        fallback = Path(rel).name if adapter == 'docs' else Path(rel).stem.replace('-', ' ')
        title = fields.get('title') or fields.get('name') or (heading.group(1).strip() if heading else fallback)
        text = fields.get('description') or first_prose(body)
        node = {'id': ('doc:' if adapter == 'docs' else 'wiki:') + rel[:-3],
                'kind': KINDS[adapter][1], 'title': title, 'source': rel,
                'durability': 'durable-logic', 'origin': 'extracted', 'data': {'path': rel}}
        if text:
            node['text'] = text[:300]
        if raw:
            node['content_hash'] = hashlib.sha256(raw.encode('utf-8', 'replace')).hexdigest()[:16]
        if adapter == 'docs':
            meta = fields.get('metadata', {})
            node['data']['type'] = (meta.get('type') if isinstance(meta, dict) else None) or fields.get('type')
            for field in ('status', 'owner'):
                if fields.get(field):
                    node[field] = fields[field]
        nodes.append(node)
    return nodes


def _names(value, key):
    if not isinstance(value, list):
        raise ValueError('source adapters: tracker names must be an array')
    out = []
    for item in value:
        name = item.get(key) if isinstance(item, dict) else item
        if not isinstance(name, str) or not name.strip():
            raise ValueError('source adapters: invalid tracker name')
        out.append(name)
    return out


def _issues(root, knowledge):
    if not _included('issues.json', knowledge):
        return []
    path = _path(root, 'issues.json')
    if not path.exists():
        if strict():
            raise ValueError('source adapters: selected issue snapshot unavailable')
        return []
    data = _json(path)
    if not isinstance(data, dict) or not isinstance(data.get('repos', []), list):
        raise ValueError('source adapters: issues repos must be an array')
    nodes = {}
    for repository in data.get('repos', []):
        repo = repository.get('repo') if isinstance(repository, dict) else None
        if not isinstance(repo, str) or not re.fullmatch(r'[^\s/#]+/[^\s/#]+', repo):
            raise ValueError('source adapters: issue needs an owner/repository identity')
        for bucket in ('open', 'recently_closed'):
            rows = repository.get(bucket, [])
            if not isinstance(rows, list):
                raise ValueError('source adapters: issue bucket must be an array')
            for row in rows:
                number = row.get('number') if isinstance(row, dict) else None
                if type(number) is not int or number <= 0:
                    raise ValueError('source adapters: issue number must be a positive integer')
                labels = _names(row.get('labels', []), 'name')
                assignees = _names(row.get('assignees', []), 'login')
                milestone = row.get('milestone')
                milestone = milestone.get('title') if isinstance(milestone, dict) else milestone
                node = {'id': f'issue:{repo}#{number}', 'kind': 'Issue',
                        'title': row.get('title') or f'#{number}', 'source': 'issues.json',
                        'durability': 'point-in-time', 'origin': 'extracted',
                        'data': {k: v for k, v in {'repo': repo, 'number': number,
                            'state': row.get('state'), 'bucket': bucket, 'url': row.get('url'),
                            'updated': row.get('updatedAt'), 'milestone': milestone,
                            'project': row.get('project'), 'assignees': assignees or None}.items() if v is not None}}
                if row.get('status') or row.get('state'):
                    node['status'] = row.get('status') or row['state']
                if labels:
                    node['labels'] = labels
                if assignees:
                    node['owner'] = assignees[0]
                if node['id'] in nodes and nodes[node['id']] != node:
                    raise ValueError('source adapters: conflicting duplicate issue identity')
                nodes[node['id']] = node
    return [nodes[key] for key in sorted(nodes)]


def activity_nodes(data, source='activity-snapshot.json'):
    """Project a frozen producer snapshot; never invent positional identities.

    Hash/id values are opaque producer keys, scoped to this brain. In particular,
    a legacy abbreviated Git hash is preserved, not certified as a full digest.
    """
    if isinstance(data, dict):
        keys = [key for key in ('events', 'activity', 'commits') if key in data]
        if len(keys) != 1:
            raise ValueError('source adapters: activity needs exactly one event array')
        rows = data[keys[0]]
    else:
        rows = data
    if not isinstance(rows, list):
        raise ValueError('source adapters: activity records must be an array')
    nodes = {}
    records = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('source adapters: invalid activity row')
        identity = row.get('hash') or row.get('id')
        if not isinstance(identity, str) or not identity.strip() or any(c.isspace() for c in identity):
            raise ValueError('source adapters: activity requires a stable string hash or id')
        for key in ('hash', 'id', 'title', 'summary', 'event', 'type', 'body', 'detail',
                    'date', 'at', 'timestamp', 'actor', 'who'):
            if row.get(key) is not None and not isinstance(row[key], str):
                raise ValueError(f'source adapters: activity {key} must be a string')
        files = row.get('files')
        if files is not None and not isinstance(files, list):
            raise ValueError('source adapters: activity files must be an array')
        title = row.get('title') or row.get('summary') or row.get('event') or row.get('type') or 'activity'
        text = row.get('body') or row.get('summary') or row.get('detail') or ''
        when = (row.get('date') or row.get('at') or row.get('timestamp') or '').strip()
        node = {'id': 'activity:' + identity, 'kind': 'ActivityEvent', 'title': title,
                'source': source, 'durability': 'point-in-time', 'origin': 'extracted',
                'data': {k: v for k, v in {'date': when, 'kind': row.get('type'),
                    'actor': row.get('actor') or row.get('who'),
                    'files': len(files) if files is not None else None}.items() if v is not None and v != ''}}
        if text:
            node['text'] = text[:300]
        if identity in records and records[identity] != row:
            raise ValueError('source adapters: conflicting duplicate activity identity')
        records[identity] = row
        nodes[identity] = node
    return [nodes[key] for key in sorted(nodes)]


def _activity(root, knowledge):
    # Respect the old source exclusion too: enrolling a snapshot must not undo
    # an existing policy that excludes the live feed.
    if not all(_included(name, knowledge) for name in ('activity.json', 'activity-snapshot.json')):
        return []
    path = _path(root, 'activity-snapshot.json')
    if not path.exists() and strict():
        raise ValueError('source adapters: selected activity snapshot unavailable')
    return activity_nodes(_json(path)) if path.exists() else []


def compile_selected(root, registry, *, frontmatter, first_prose):
    root = Path(root).resolve()
    path = root / 'client.config.json'
    config = _json(_path(root, 'client.config.json')) if path.exists() else {}
    if not isinstance(config, dict) or not isinstance(config.get('brain', {}), dict):
        raise ValueError('source adapters: invalid brain configuration')
    selected = config.get('brain', {}).get('sourceAdapters', [])
    if not isinstance(selected, list) or any(not isinstance(s, str) or s not in KINDS for s in selected):
        raise ValueError('source adapters: unsupported sourceAdapters selection')
    if len(set(selected)) != len(selected):
        raise ValueError('source adapters: duplicate adapter selection')
    if not selected:
        return []
    knowledge = config.get('knowledge', {})
    if not isinstance(knowledge, dict):
        raise ValueError('source adapters: invalid knowledge configuration')
    nodes = []
    for name in selected:
        semantic, compiled = KINDS[name]
        if registry is None or registry.kinds.get(semantic, {}).get('node') != compiled:
            raise ValueError(f'source adapters: {name} requires its composed node mapping')
        if name == 'issues':
            nodes.extend(_issues(root, knowledge))
        elif name == 'activity':
            nodes.extend(_activity(root, knowledge))
        else:
            nodes.extend(_markdown(root, knowledge, name, frontmatter, first_prose))
    registry.validate_records(nodes, [])
    return nodes
