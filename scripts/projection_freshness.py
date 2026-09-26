"""Source-bound observations for the local enriched-KG refresh scope only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

RECEIPT = '_internal/kg-refresh-receipt.json'
OUTPUTS = ('app/knowledge_graph.json', 'app/kg-references.json', 'app/brain.json')
COMMANDS = (('scripts/build-kg.py', '--require-source'), ('scripts/curate-kg.py',), ('scripts/gen-brain.py',))
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_FILES = 20000


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def local(root, relative):
    if not isinstance(relative, str) or not relative:
        raise ValueError('projection inputs must be local relative paths')
    path = Path(relative)
    if path.is_absolute() or '..' in path.parts or relative == '.':
        raise ValueError('projection inputs must be local relative paths')
    if root.is_symlink() or any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise ValueError('projection observations cannot follow symlinks')
    return root / path


def file_hash(root, relative):
    path = local(root, relative)
    if not path.exists():
        return None
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError('projection input is not a bounded regular file')
    before = path.stat()
    digest, size = hashlib.sha256(), 0
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            size += len(chunk)
            if size > MAX_FILE_BYTES:
                raise ValueError('projection input exceeds observation size limit')
            digest.update(chunk)
    after = path.stat()
    if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise ValueError('projection input changed during observation')
    return digest.hexdigest()


def tree_hashes(root, relative, *, python_only=False):
    path = local(root, relative)
    if not path.exists():
        return None
    if not path.is_dir():
        raise ValueError('projection source tree is not a directory')
    result, count = {}, 0

    def unreadable(error):
        raise error

    # Do not use glob traversal that can silently suppress unreadable directories.
    for directory, children, names in os.walk(path, onerror=unreadable, followlinks=False):
        children[:] = [name for name in children if name != '__pycache__']
        for name in children + names:
            count += 1
            if count > MAX_FILES:
                raise ValueError('projection source tree exceeds observation limit')
            item = Path(directory) / name
            relative_name = item.relative_to(root).as_posix()
            local(root, relative_name)
            if item.is_file() and (not python_only or item.suffix == '.py'):
                result[relative_name] = file_hash(root, relative_name)
    return result


def inputs(root):
    names = ('knowledge-base/knowledge_graph_enriched.json', 'knowledge/curation.json',
             'client.config.json', 'brain-schema.json')
    files = {name: file_hash(root, name) for name in names}
    config = json.loads(local(root, 'client.config.json').read_text()) if files['client.config.json'] else {}
    if not isinstance(config, dict) or not isinstance(config.get('knowledge', {}), dict):
        raise ValueError('invalid projection source configuration')
    wiki = config.get('knowledge', {}).get('wikiDir') or 'knowledge/wiki'
    result = {'files': files, 'wikiPath': wiki, 'wiki': tree_hashes(root, wiki),
              'engine': tree_hashes(root, 'scripts', python_only=True),
              'schemas': tree_hashes(root, 'schemas')}
    # Configuration chooses which directory is read; fence it across that read.
    if files['client.config.json'] != file_hash(root, 'client.config.json'):
        raise ValueError('projection configuration changed during observation')
    return result


def outputs(root):
    return {name: file_hash(root, name) for name in OUTPUTS}


def require_inputs(value):
    for path in ('knowledge-base/knowledge_graph_enriched.json', 'knowledge/curation.json'):
        if value['files'][path] is None:
            raise ValueError('required projection input unavailable')
    if not value['engine'] or any(command[0] not in value['engine'] for command in COMMANDS):
        raise ValueError('required projection engine unavailable')


def validate_receipt(receipt):
    if (not isinstance(receipt, dict) or set(receipt) != {'protocolVersion', 'scope', 'inputs', 'outputs'}
            or receipt['protocolVersion'] != '1.0' or receipt['scope'] != 'enriched-knowledge-graph'):
        raise ValueError('invalid projection receipt')
    source = receipt['inputs']
    if not isinstance(source, dict) or set(source) != {'files', 'wikiPath', 'wiki', 'engine', 'schemas'}:
        raise ValueError('invalid projection source coverage')
    if not isinstance(source['wikiPath'], str) or not source['wikiPath']:
        raise ValueError('invalid projection wiki path')
    names = {'knowledge-base/knowledge_graph_enriched.json', 'knowledge/curation.json',
             'client.config.json', 'brain-schema.json'}
    if (not isinstance(source['files'], dict) or set(source['files']) != names
            or not isinstance(receipt['outputs'], dict) or set(receipt['outputs']) != set(OUTPUTS)):
        raise ValueError('invalid projection file coverage')
    for table in (source['files'], source['wiki'], source['engine'], source['schemas'], receipt['outputs']):
        if table is None:
            continue
        if not isinstance(table, dict) or any(not isinstance(key, str) or not key
                or value is not None and (not isinstance(value, str) or not re.fullmatch(r'[a-f0-9]{64}', value))
                for key, value in table.items()):
            raise ValueError('invalid projection file revision')
    require_inputs(source)
    if any(value is None for value in receipt['outputs'].values()):
        raise ValueError('incomplete projection receipt')


def refresh(root):
    """Run the existing ordered pipeline and publish a receipt only on success.

    Operators must use a disposable/quiescent build copy. Source hashes fence
    ordinary concurrent edits; this is not a transactional source filesystem.
    """
    root = Path(root)
    destination = local(root, RECEIPT)
    before = inputs(root)
    require_inputs(before)
    for command in COMMANDS:
        subprocess.run([sys.executable, *command], cwd=root, check=True)
    after = inputs(root)
    if before != after:
        raise ValueError('projection inputs changed during refresh; receipt was not advanced')
    observed = outputs(root)
    if any(value is None for value in observed.values()):
        raise ValueError('projection pipeline omitted a required output')
    graph = json.loads(local(root, OUTPUTS[0]).read_text())
    brain = json.loads(local(root, OUTPUTS[2]).read_text())
    expected = {'kg:' + str(node['id']) for node in graph['nodes']}
    actual = {node['id'] for node in brain['nodes'] if node.get('source') == OUTPUTS[0]}
    if expected != actual:
        raise ValueError('compiled brain omitted or added KG identities')
    if inputs(root) != before or outputs(root) != observed:
        raise ValueError('projection inputs or outputs changed before receipt publication')
    receipt = {'protocolVersion': '1.0', 'scope': 'enriched-knowledge-graph',
               'inputs': before, 'outputs': observed}
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.kg-refresh-', dir=destination.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write('\n')
        os.replace(temporary, destination)
    finally:
        Path(temporary).unlink(missing_ok=True)
    return receipt


def observe(root, *, brain_sha256=None):
    """No writes. Current means matching declared local inputs, never source age."""
    root = Path(root)
    evidence = {}

    def result(state, reason):
        return {'scope': 'enriched-knowledge-graph', 'state': state, 'reason': reason,
                'basis': fingerprint(evidence)}

    try:
        evidence['inputs'] = inputs(root)
        require_inputs(evidence['inputs'])
        evidence['outputs'] = outputs(root)
        if any(value is None for value in evidence['outputs'].values()):
            return result('unknown', 'projection-output-unavailable')
        path = local(root, RECEIPT)
        if file_hash(root, RECEIPT) is None:
            return result('unknown', 'projection-receipt-unavailable')
        if path.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('projection receipt exceeds size limit')
        receipt = json.loads(path.read_text())
        validate_receipt(receipt)
        evidence['receipt'] = fingerprint(receipt)
        if receipt['inputs'] != evidence['inputs']:
            return result('stale', 'projection-inputs-changed')
        if receipt['outputs'] != evidence['outputs']:
            return result('stale', 'projection-outputs-changed')
        if brain_sha256 is not None and brain_sha256 != receipt['outputs'][OUTPUTS[2]]:
            return result('stale', 'projection-brain-unbound')
        return result('current', 'declared-local-inputs-match')
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError):
        return result('unknown', 'projection-inputs-or-receipt-unavailable')


def observe_delivered(root, binding, store=None):
    """Receipted delivered projections (#228): freshness is outbox lag, never file age.

    Without an authority to read, the lag is unknown. A negative lag means the
    receipt claims a sequence the authority never reached; the receipt gate fails it.
    """
    from projection_receipts import load
    observed = []
    for consumer, payload, receipt in load(root, binding):
        entry = {'consumer': consumer, 'sequence': receipt['sequence'], 'head': None, 'lag': None,
                 'state': 'unknown', 'reason': 'authority-unavailable'}
        if store is not None:
            head = store.delivery_preview(payload['audience'])['sequence']
            lag = (head or 0) - (receipt['sequence'] or 0)
            if lag == 0:
                state, reason = 'current', 'outbox-delivered'
            elif lag > 0:
                state, reason = 'stale', 'outbox-lag'
            else:
                state, reason = 'invalid', 'receipt-ahead-of-authority'
            entry.update(head=head, lag=lag, state=state, reason=reason)
        observed.append(entry)
    return observed
