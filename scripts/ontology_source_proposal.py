"""Operator-only versioned source proposal; no native/file authority adoption.

Registry definitions are source declarations. Ordinary Term/glossary records use
those records' own canonical writers instead. This builder writes a fresh private
proposal outside the inspected root; normal source Git review/apply remains an
explicit operator action, never inferred from this artifact or caller claims.
"""
from copy import deepcopy
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat

from context_host import decode
from ontology import Registry
from brain_upgrade import OBLIGATIONS

MAX_FILE = 1024 * 1024
MAX_TOTAL = 4 * 1024 * 1024
MAX_INTENT = 128 * 1024
ROOT = Path(__file__).resolve().parents[1]
VALIDATION_PATHS = ('scripts/ontology_source_proposal.py', 'scripts/compose-schema.py', 'scripts/ontology.py',
                    'scripts/context_host.py', 'scripts/brain_upgrade.py',
                    'schemas/brain-node.schema.json', 'schemas/brain-edge.schema.json',
                    'schemas/brain-envelope.schema.json', 'schemas/evidence.schema.json')


class SourceProposalError(ValueError):
    pass


def _require(value, message):
    if not value:
        raise SourceProposalError(message)


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_uid, info.st_nlink)


def _stable(path, cap=MAX_FILE, *, trusted=False):
    """Read one source by nofollow component FDs and stable opened/named identity."""
    path = Path(path).absolute()
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        name = path.parts[-1]
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        _require(stat.S_ISREG(before.st_mode) and before.st_uid in ((0, os.geteuid()) if trusted else (os.geteuid(),)) and
                 before.st_nlink == 1 and not before.st_mode & 0o022 and before.st_size <= cap,
                 'Source must be bounded, owned, regular, single-link and not group/other writable')
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            _require(_identity(os.fstat(fd)) == _identity(before), 'Source replaced before open')
            chunks, remaining = [], before.st_size + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b''.join(chunks)
            _require(len(raw) == before.st_size and _identity(os.fstat(fd)) == _identity(before),
                     'Source changed during read')
        finally:
            os.close(fd)
        _require(_identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False)) == _identity(before),
                 'Source name changed during read')
        return raw, {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
                     'mode': stat.S_IMODE(before.st_mode)}
    finally:
        os.close(descriptor)


def _composer():
    # Trusted installed engine code only; never import a module from inspected root.
    path = ROOT / 'scripts/compose-schema.py'
    spec = importlib.util.spec_from_file_location('_mimwell_ontology_source_composer', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _text(value, bound=2000):
    return isinstance(value, str) and bool(value.strip()) and len(value) <= bound


def _revision(value):
    _require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value),
             'An exact source semantic revision is required')
    return tuple(int(part) for part in value.split('.'))


def _spans(text):
    """Bounded syntax spans only. Source validation is the canonical JSON decoder."""
    decoder = json.JSONDecoder()
    count = 0

    def whitespace(index):
        while index < len(text) and text[index] in ' \r\n\t':
            index += 1
        return index

    def node(index, depth=0):
        nonlocal count
        index = whitespace(index)
        count += 1
        _require(depth <= 64 and count <= 32768, 'Source syntax exceeds proposal bound')
        result = {'start': index}
        if text[index] == '{':
            props = {}
            current = whitespace(index + 1)
            while text[current] != '}':
                key, after = decoder.raw_decode(text, current)
                _require(isinstance(key, str), 'Invalid source object')
                colon = whitespace(after)
                _require(text[colon] == ':', 'Invalid source object')
                child = node(colon + 1, depth + 1)
                props[key] = child
                current = whitespace(child['end'])
                if text[current] == '}':
                    break
                _require(text[current] == ',', 'Invalid source object')
                current = whitespace(current + 1)
            result.update(properties=props, end=current + 1)
        elif text[index] == '[':
            items = []
            current = whitespace(index + 1)
            while text[current] != ']':
                child = node(current, depth + 1)
                items.append(child)
                current = whitespace(child['end'])
                if text[current] == ']':
                    break
                _require(text[current] == ',', 'Invalid source array')
                current = whitespace(current + 1)
            result.update(items=items, end=current + 1)
        else:
            _, end = decoder.raw_decode(text, index)
            result['end'] = end
        return result

    root = node(0)
    _require(not text[root['end']:].strip(), 'Trailing source content')
    return root


def _patch_source(raw, candidate, append, revision):
    """Change only selected syntax spans; preserve opaque unrelated JSON bytes."""
    text = raw.decode('utf-8')
    tree = _spans(text)
    rev = tree['properties']['revision']
    edits = [(rev['start'], rev['end'], json.dumps(revision))]
    insertions = {}
    for path, values in append.items():
        at, data, index = tree, candidate, 0
        while index < len(path):
            part = path[index]
            children = at.get('items') if isinstance(part, int) else at.get('properties', {})
            exists = (isinstance(children, list) and 0 <= part < len(children)
                      if isinstance(part, int) else part in children)
            if not exists:
                _require(not isinstance(part, int) and 'properties' in at, 'Unsupported insertion path')
                value = data[part]
                insertions.setdefault(at['end'] - 1, {'count': len(at['properties']), 'rows': []})['rows'].append((part, value))
                break
            at = children[part]
            data = data[part]
            index += 1
        else:
            _require('items' in at, 'Proposal target is not an array')
            encoded = ','.join(json.dumps(value, ensure_ascii=False, allow_nan=False) for value in values)
            edits.append((at['end'] - 1, at['end'] - 1, (',' if at['items'] else '') + encoded))
    for position, item in insertions.items():
        # Multiple missing id-convention children may share their first missing ancestor.
        unique = dict(item['rows'])
        content = ','.join(json.dumps(key) + ':' + json.dumps(value, ensure_ascii=False, allow_nan=False)
                           for key, value in unique.items())
        edits.append((position, position, (',' if item['count'] else '') + content))
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    result = text.encode('utf-8')
    _require(decode(result) == candidate and len(result) <= MAX_FILE, 'Proposed source mismatch or size limit')
    return result


def prepare(root, layer, intent, next_revision):
    """Validate additive definitions and return a source-bound proposal, not approval."""
    root = Path(root).absolute()
    _require(root.resolve(strict=True) == root, 'Inspected root must be normalized and nonsymlinked')
    _require(isinstance(intent, dict) and set(intent) == {
        'format', 'expectedOntologySha256', 'changes', 'reason', 'evidence'}, 'Unexpected source intent fields')
    _require(intent['format'] == 'ontology-source-intent/v1' and _text(intent['reason']) and
             isinstance(intent['evidence'], list) and 1 <= len(intent['evidence']) <= 32 and
             all(_text(value) for value in intent['evidence']), 'Bounded intent/reason/evidence required')
    _require(len(json.dumps(intent, ensure_ascii=False, allow_nan=False).encode()) <= MAX_INTENT,
             'Source intent exceeds bound')
    config_raw, config_pin = _stable(root / 'client.config.json')
    config = decode(config_raw)
    profile = config.get('profile')
    _require(isinstance(profile, dict), 'Use the existing explicit manual source workflow for an uncomposed registry')
    base, overlays = profile.get('base', 'core'), profile.get('overlays', [])
    _require(isinstance(overlays, list) and 1 <= len(overlays) <= 31, 'Select actual composed source layers first')
    names = [base, *overlays]
    _require(len(names) == len(set(names)) and all(isinstance(name, str) and
             re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name) for name in names) and layer in names,
             'Source layer is not in the actual composition')
    documents, raws, pins = {}, {}, {'client.config.json': config_pin}
    total = len(config_raw)
    for name in names:
        relative = 'profiles/' + name + '.json'
        raw, row = _stable(root / relative)
        total += len(raw)
        _require(total <= MAX_TOTAL, 'Source closure exceeds four MiB')
        document = decode(raw)
        _require(isinstance(document, dict) and document.get('overlay') == name, 'Invalid selected source layer')
        documents[name], raws[name], pins[relative] = document, raw, row
    validation = {}
    for name in VALIDATION_PATHS:
        _, validation[name] = _stable(ROOT / name, trusted=True)
    composer = _composer()
    try:
        before = composer.compose(base, overlays, _load_layer=lambda name: deepcopy(documents[name]))
    except composer.CompositionError as exc:
        raise SourceProposalError(str(exc)) from None
    registry = Registry(before)
    _require(intent['expectedOntologySha256'] == registry.binding()['sha256'], 'Ontology source changed')
    original = documents[layer]
    _require(_revision(next_revision)[:2] > _revision(original.get('revision'))[:2],
             'Additive vocabulary/kind proposals require a newer minor or major source revision')
    changes = intent['changes']
    _require(isinstance(changes, list) and 1 <= len(changes) <= 64, 'Expected bounded typed source changes')
    candidate = deepcopy(original)
    candidate['revision'] = next_revision
    append = {}
    for change in changes:
        _require(isinstance(change, dict), 'Invalid typed source change')
        if change.get('op') == 'add-term':
            _require(set(change) == {'op', 'term'} and isinstance(change['term'], dict), 'Invalid term proposal')
            term = deepcopy(change['term'])
            _require(set(term) <= {'id', 'scheme', 'label', 'definition', 'aliases', 'broader'} and
                     all(_text(term.get(key)) for key in ('id', 'scheme', 'label', 'definition')) and
                     term['id'] not in registry.terms, 'New term requires a fresh identity and definition')
            candidate.setdefault('taxonomy', []).append(term)
            append.setdefault(('taxonomy',), []).append(term)
        elif change.get('op') == 'add-aliases':
            _require(set(change) == {'op', 'term', 'aliases'} and isinstance(change['aliases'], list) and
                     1 <= len(change['aliases']) <= 64 and all(_text(value) for value in change['aliases']),
                     'Invalid alias proposal')
            terms = original.get('taxonomy', [])
            indices = [i for i, row in enumerate(terms) if row.get('id') == change['term']]
            _require(len(indices) == 1, 'Select the source layer that actually owns this term')
            index = indices[0]
            aliases = candidate['taxonomy'][index].setdefault('aliases', [])
            _require(not set(aliases) & set(change['aliases']) and len(set(change['aliases'])) == len(change['aliases']),
                     'Alias proposal repeats existing values')
            aliases.extend(change['aliases'])
            append.setdefault(('taxonomy', index, 'aliases'), []).extend(change['aliases'])
        elif change.get('op') == 'add-kind':
            _require(set(change) == {'op', 'kind', 'idConvention'} and isinstance(change['kind'], dict),
                     'Invalid kind proposal')
            kind = deepcopy(change['kind'])
            _require(_text(kind.get('id')) and re.fullmatch(r'[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+', kind['id']) and
                     kind['id'] not in registry.kinds and isinstance(kind.get('payloadSchema'), dict) and
                     change['idConvention'] in before['contract']['idConventions'],
                     'New kinds require a fresh namespaced identity, actual payload schema and declared identity convention')
            candidate.setdefault('kinds', []).append(kind)
            append.setdefault(('kinds',), []).append(kind)
            candidate.setdefault('idConventions', {}).setdefault(change['idConvention'], []).append(kind['id'])
            append.setdefault(('idConventions', change['idConvention']), []).append(kind['id'])
        elif change.get('op') == 'add-edge':
            _require(set(change) == {'op', 'edge'} and isinstance(change['edge'], dict), 'Invalid edge proposal')
            edge = deepcopy(change['edge'])
            _require(_text(edge.get('id')) and re.fullmatch(r'[a-z][a-z0-9_-]*(?:\.[a-z][a-z0-9_-]*)+', edge['id']) and
                     edge['id'] not in registry.edges and all(isinstance(edge.get(side), list) and edge[side]
                     for side in ('domain', 'range')), 'New relations require a fresh namespaced id and explicit domain/range')
            candidate.setdefault('edges', []).append(edge)
            append.setdefault(('edges',), []).append(edge)
        else:
            raise SourceProposalError('Unsupported source change; removals and identity/meaning migrations use the full upgrade workflow')
    updated = {**documents, layer: candidate}
    try:
        after = composer.compose(base, overlays, _load_layer=lambda name: deepcopy(updated[name]))
    except composer.CompositionError as exc:
        raise SourceProposalError(str(exc)) from None
    target = Registry(after)
    for category in ('kinds', 'edges'):
        old_rows, new_rows = getattr(registry, category), getattr(target, category)
        _require(all(value == new_rows[key] for key, value in old_rows.items()), 'Existing declarations must remain unchanged')
    for identity, value in registry.terms.items():
        observed = target.terms[identity]
        _require({k: v for k, v in value.items() if k != 'aliases'} ==
                 {k: v for k, v in observed.items() if k != 'aliases'} and
                 set(value.get('aliases', [])) <= set(observed.get('aliases', [])),
                 'Existing term identity/meaning cannot be rewritten by this additive proposal')
    proposed_raw = _patch_source(raws[layer], candidate, append, next_revision)
    relative = 'profiles/' + layer + '.json'
    diff = []
    for line in difflib.unified_diff(raws[layer].decode().splitlines(True), proposed_raw.decode().splitlines(True),
                                     fromfile='a/' + relative, tofile='b/' + relative):
        diff.append(line if line.endswith('\n') else line + '\n\\ No newline at end of file\n')
    report = {'format': 'ontology-source-proposal/v1', 'sourceLayer': layer, 'sourcePath': relative,
              'nextSourceRevision': next_revision,
              'sourcePins': pins, 'validationPins': validation, 'beforeOntology': registry.binding(), 'afterOntology': target.binding(),
              'candidateSha256': hashlib.sha256(proposed_raw).hexdigest(),
              'patchSha256': hashlib.sha256(''.join(diff).encode()).hexdigest(),
              'originalIntent': deepcopy(intent),
              'intentSha256': hashlib.sha256(json.dumps(intent, sort_keys=True, separators=(',', ':'),
                                                       ensure_ascii=False, allow_nan=False).encode()).hexdigest(),
              'reason': intent['reason'], 'evidenceClaims': intent['evidence'],
              'requiredReview': sorted(set(OBLIGATIONS['ontologyLayer'] + OBLIGATIONS['term'] +
                                          OBLIGATIONS['kind'] + OBLIGATIONS['edge'])),
              'compatibility': 'additive structural validation only; actual records/policy/consumers require separate conformance',
              'writer': 'normal-source-Git-review-workflow', 'approval': None, 'adopted': False,
              'nativeMutations': False, 'ordinaryTermRecords': 'use their declared record/file writer; not this Registry-definition route'}
    verify_current(root, report)
    return report, proposed_raw, ''.join(diff).encode()


def verify_current(root, proposal):
    for relative, expected in proposal['sourcePins'].items():
        _require(relative == 'client.config.json' or re.fullmatch(r'profiles/[A-Za-z0-9][A-Za-z0-9._-]{0,63}\.json', relative),
                 'Invalid source pin path')
        _, actual = _stable(Path(root) / relative)
        _require(actual == expected, 'Source changed before operator handoff: ' + relative)
    for relative, expected in proposal['validationPins'].items():
        _require(relative in VALIDATION_PATHS, 'Invalid validation pin')
        _, actual = _stable(ROOT / relative, trusted=True)
        _require(actual == expected, 'Trusted validation implementation changed')


def write_proposal(root, output, report, candidate, patch):
    """New private files only; no source mutation or claimed human approval."""
    root, output = Path(root).absolute(), Path(output).absolute()
    _require(not output.is_relative_to(root), 'Proposal output must be outside inspected source root')
    _require(hashlib.sha256(candidate).hexdigest() == report['candidateSha256'] and
             hashlib.sha256(patch).hexdigest() == report['patchSha256'], 'Proposal payload changed')
    verify_current(root, report)
    # Explicit output parent is existing; no symlink parent traversal.
    _require(output.parent.resolve(strict=True) == output.parent, 'Proposal parent cannot follow symlinks')
    os.mkdir(output, 0o700)
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory_identity = (os.fstat(directory).st_dev, os.fstat(directory).st_ino)
    try:
        for name, raw in [('candidate.json', candidate), ('source.patch', patch),
                          ('proposal.json', (json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + '\n').encode())]:
            _require(len(raw) <= MAX_TOTAL, 'Proposal artifact exceeds bound')
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            observed, info = _stable(output / name, cap=MAX_TOTAL)
            named = output.lstat()
            _require(observed == raw and info['mode'] == 0o600 and stat.S_ISDIR(named.st_mode) and
                     (named.st_dev, named.st_ino) == directory_identity, 'Private proposal readback/identity failed')
        os.fsync(directory)
    finally:
        os.close(directory)
    verify_current(root, report)
    named = output.lstat()
    _require(stat.S_ISDIR(named.st_mode) and stat.S_IMODE(named.st_mode) == 0o700 and
             named.st_uid == os.geteuid() and (named.st_dev, named.st_ino) == directory_identity,
             'Proposal directory identity changed before handoff')
    return {'format': 'ontology-source-handoff/v1', 'output': str(output), 'sourcePath': report['sourcePath'],
            'candidateSha256': report['candidateSha256'], 'patchSha256': report['patchSha256'],
            'sourceUnchanged': True, 'approval': None, 'adopted': False,
            'instruction': 'Inspect exact source.patch, obtain normal source-owner review, use ordinary Git apply/check in the source feature workflow, recompose/validate/compare, then explicitly adopt only through the qualified authority upgrade workflow.'}
