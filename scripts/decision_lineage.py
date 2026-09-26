"""Append-only decision revisions and deterministic, per-aspect lineage.

Resolution describes the authorized, recorded history. It does not establish a
business mandate or infer missing decisions. Repository review owns file writes;
this module never mutates a decision or bypasses a structured store's writer.
"""
from __future__ import annotations

from copy import deepcopy
import datetime as dt
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from ontology import _acyclic

ROOT = Path(__file__).resolve().parents[1]
KIND = 'DecisionRevision'
PREFIX = 'decision.revision:'
RELATIONS = {'amends': 'decision.amends', 'supersedes': 'supersedes', 'reverses': 'decision.reverses'}
MAX_REVISIONS = 2000


class DecisionError(ValueError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def instant(value):
    try:
        at = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
        if at.utcoffset() is None:
            raise ValueError('Timezone required')
        return at.astimezone(dt.timezone.utc)
    except (ValueError, TypeError, AttributeError) as exc:
        raise DecisionError('Invalid decision timestamp') from exc


def aspects(row):
    return set(row['values']) | set(row['withdraws'])


def overlapping(fields):
    return any('/'.join(parts[:i]) in fields for field in fields
               for parts in [field.split('/')] for i in range(2, len(parts)))


def validate(document, *, previous=None, expected_revision=None):
    schema = json.loads((ROOT / 'schemas/decision-lineage.schema.json').read_text())
    if not Draft202012Validator(schema, format_checker=FormatChecker()).is_valid(document):
        raise DecisionError('Invalid decision-lineage document')
    digest(document)  # Refuse nonfinite values even for open JSON values.
    rows = document['decisions']
    if len(rows) > MAX_REVISIONS:
        raise DecisionError('Decision revision limit exceeded')
    indexed = {row['id']: row for row in rows}
    if len(indexed) != len(rows):
        raise DecisionError('Duplicate decision revision identity')
    families, graph, family_fields = {}, {}, {}
    pins = {identity: digest(row) for identity, row in indexed.items()}
    for row in rows:
        family = (row['subject'], row['scope'])
        if families.setdefault(row['decision'], family) != family:
            raise DecisionError('A decision identity cannot cross subject or scope')
        at = instant(row['recordedAt'])
        if instant(row['review']['at']) > at:
            raise DecisionError('Review cannot follow its recorded revision')
        fields = aspects(row)
        if not fields or set(row['values']) & set(row['withdraws']):
            raise DecisionError('Each aspect needs exactly one value or withdrawal')
        # JSON pointers are canonical and cannot make parent/child claims overlap.
        family_fields.setdefault(row['decision'], set()).update(fields)
        if overlapping(fields):
            raise DecisionError('Overlapping decision aspect pointers')
        graph[row['id']] = []
        touched, withdrawn, target_fields = set(), set(), set()
        for change in row['changes']:
            target = indexed.get(change['target'])
            if target is None or target['id'] == row['id']:
                raise DecisionError('Missing or self-referencing decision predecessor')
            if target['decision'] != row['decision']:
                raise DecisionError('A change cannot replace another decision family')
            if row['review']['state'] == 'accepted' and target['review']['state'] != 'accepted':
                raise DecisionError('An accepted change requires an accepted predecessor')
            if pins[target['id']] != change['sha256']:
                raise DecisionError('Pinned decision predecessor changed')
            if instant(target['recordedAt']) > at or instant(target['effectiveFrom']) > instant(row['effectiveFrom']):
                raise DecisionError('A change cannot precede its predecessor')
            affected = set(change['fields'])
            if not affected <= aspects(target) or not affected <= fields:
                raise DecisionError('Change fields must exist in both revisions')
            pair = (change['target'], change['relation'])
            if pair in touched:
                raise DecisionError('Duplicate decision change; consolidate its fields')
            touched.add(pair)
            keys = {(change['target'], field) for field in affected}
            if target_fields & keys:
                raise DecisionError('An aspect cannot have multiple effects on the same predecessor')
            target_fields |= keys
            if change['relation'] == 'supersedes' and affected != aspects(target):
                raise DecisionError('Partial replacement must use amends or reverses')
            if change['relation'] == 'reverses':
                if not affected <= set(row['withdraws']):
                    raise DecisionError('Reversal must explicitly withdraw each named aspect')
                withdrawn |= affected
            elif not affected <= set(row['values']):
                raise DecisionError('Amendment/replacement must supply explicit values')
            graph[row['id']].append(target['id'])
        if withdrawn != set(row['withdraws']):
            raise DecisionError('Withdrawal requires an explicit reversal predecessor')
    # Reject overlap across revisions too; otherwise a parent assertion could
    # silently compete with a child assertion without appearing as a conflict.
    for fields in family_fields.values():
        if overlapping(fields):
            raise DecisionError('Decision history mixes overlapping aspect pointers')
    _acyclic(graph, 'decision lineage')
    if previous is not None:
        validate(previous)
        if expected_revision != digest(previous):
            raise DecisionError('Expected decision history revision does not match')
        for row in previous['decisions']:
            if indexed.get(row['id']) != row:
                raise DecisionError('Decision history is append-only; preserve every original revision')
    elif expected_revision is not None:
        raise DecisionError('An expected revision requires the previous document')
    return indexed


def edges_for(rows):
    edges = []
    for row in rows:
        for change in row['changes']:
            edges.append({'source': PREFIX + row['id'], 'target': PREFIX + change['target'],
                          'rel': RELATIONS[change['relation']],
                          'data': {'fields': sorted(change['fields']), 'predecessorSha256': change['sha256']}})
        if row['legacyDecision'] is not None:
            edges.append({'source': PREFIX + row['id'], 'target': row['legacyDecision'],
                          'rel': 'decision.revision_of'})
    return sorted(edges, key=lambda e: (e['source'], e['target'], e['rel']))


def compile_edges(root, registry, nodes):
    """An explicitly selected overlay participates in the ordinary compilation."""
    if 'decision.revision' not in registry.kinds:
        return []
    from context_host import _read
    descriptor = registry.kinds['decision.revision']
    if descriptor.get('node') != KIND:
        raise DecisionError('Unsupported decision revision kind mapping')
    document = _read(Path(root), descriptor['artifact'])
    rows = validate(document)
    compiled = {n['id']: n for n in nodes}
    for identity, row in rows.items():
        if compiled.get(PREFIX + identity, {}).get('data') != row:
            raise DecisionError('Decision revision compiler differs from canonical input')
        legacy = row['legacyDecision']
        if legacy is not None and compiled.get(legacy, {}).get('kind') != 'Decision':
            raise DecisionError('Legacy decision anchor is unavailable')
    return edges_for(document['decisions'])


def unavailable():
    # Unknown and denied families deliberately share the same response.
    return {'protocolVersion': '1.0', 'state': 'unavailable', 'positions': [], 'history': [],
            'edges': [], 'gaps': ['Decision history is unavailable in this authorized view.']}


def trace(brain, decision, *, boundary, effective_at, known_at, snapshot_at,
          max_revisions=200, max_bytes=262144):
    """Resolve one complete visible family with current read authorization.

    effective_at selects when a position applies. known_at selects what had been
    recorded/reviewed, bounded by snapshot_at. Neither changes read grants.
    """
    effective, known, snapshot = map(instant, (effective_at, known_at, snapshot_at))
    if known > snapshot:
        raise DecisionError('Known-at exceeds the pinned snapshot')
    if type(max_revisions) is not int or not 1 <= max_revisions <= MAX_REVISIONS:
        raise DecisionError('Invalid decision traversal limit')
    if type(max_bytes) is not int or not 1024 <= max_bytes <= 4194304:
        raise DecisionError('Invalid decision output limit')
    all_nodes = [n for n in brain['nodes'] if n['kind'] == KIND]
    validate({'protocolVersion': '1.0', 'decisions': [n['data'] for n in all_nodes]})
    if any(n['id'] != PREFIX + n['data']['id'] for n in all_nodes):
        raise DecisionError('Decision node identity differs from canonical revision')
    family = [n for n in all_nodes if n['data']['decision'] == decision]
    if not family:
        return unavailable()
    visible = boundary.graph(brain)
    readable = {n['id'] for n in visible['nodes']}
    expected_edges = edges_for([n['data'] for n in family])
    family_ids = {n['id'] for n in family}
    lineage_relations = {*RELATIONS.values(), 'decision.revision_of'}
    actual_edges = [e for e in brain['edges'] if e['rel'] in lineage_relations
                    and (e['source'] in family_ids or e['target'] in family_ids)]
    def edge_key(e):
        return e['source'], e['target'], e['rel']
    public_edges = {edge_key(e): e for e in visible['edges']}
    if (any(n['id'] not in readable for n in family)
            or any(not boundary.permits('assertions', claim) for n in family for claim in n['data']['evidence'])
            or any(edge_key(e) not in public_edges for e in [*expected_edges, *actual_edges])):
        return unavailable()
    if (len(actual_edges) != len(expected_edges)
            or {edge_key(e) for e in actual_edges} != {edge_key(e) for e in expected_edges}):
        raise DecisionError('Decision graph contains undeclared or duplicate lineage edges')
    if len(family) > max_revisions:
        return {**unavailable(), 'state': 'limited', 'gaps': ['Decision traversal limit exceeded; no current position asserted.']}
    # Verify edge metadata rather than trusting a producer's relation label.
    for e in expected_edges:
        actual = public_edges[edge_key(e)]
        if actual.get('data') != e.get('data'):
            raise DecisionError('Decision graph edges disagree with revision history')
    selected = {n['data']['id']: n for n in family if instant(n['data']['recordedAt']) <= known}
    eligible = {identity: n for identity, n in selected.items()
                if n['data']['review']['state'] == 'accepted' and instant(n['data']['effectiveFrom']) <= effective}
    effects, replaced = {}, set()
    for identity, node in eligible.items():
        row = node['data']
        for field in aspects(row):
            effects[(identity, field)] = {'revision': node['id'], 'withdrawn': field in row['withdraws'],
                                         **({'value': deepcopy(row['values'][field])} if field in row['values'] else {})}
        for change in row['changes']:
            # A proposed or not-yet-known predecessor is not an operative value.
            for field in change['fields']:
                replaced.add((change['target'], field))
    fields = sorted({field for _, field in effects})
    positions = []
    for field in fields:
        alternatives = [effects[key] for key in sorted(effects) if key[1] == field and key not in replaced]
        state = 'conflict' if len(alternatives) > 1 else 'withdrawn' if alternatives[0]['withdrawn'] else 'resolved'
        positions.append({'field': field, 'state': state, 'alternatives': alternatives})
    gaps, history = [], []
    from context_bundle import _evidence_gaps
    for identity, node in sorted(selected.items()):
        row = node['data']
        bundle = node.get('evidence', {})
        claims = {a['id']: a for a in bundle.get('assertions', [])}
        if not row['evidence'] or set(row['evidence']) - claims.keys():
            gaps.append({'revision': node['id'], 'reason': 'missing-linked-evidence'})
        # Shared evidence validation/support semantics, with separate clocks for
        # the availability of an attestation and applicability of its claim.
        for gap in _evidence_gaps(node, node['id'], known):
            if gap['reason'] not in ('outside-validity', 'no-evidence'):
                reason = 'asserted-after-known-at' if gap['reason'] == 'asserted-after-as-of' else gap['reason']
                gaps.append({'revision': node['id'], 'reason': reason, 'state': gap['state']})
        for attestation in bundle.get('attestations', []):
            start, end = attestation['validity']['from'], attestation['validity']['until']
            if (start and effective < instant(start)) or (end and effective >= instant(end)):
                gaps.append({'revision': node['id'], 'reason': 'outside-effective-validity'})
            reviewed = attestation['review']['at']
            if not reviewed or instant(reviewed) > known:
                gaps.append({'revision': node['id'], 'reason': 'review-unavailable-at-known-time'})
        for source in bundle.get('sources', []):
            if source['capturedAt'] and instant(source['capturedAt']) > known:
                gaps.append({'revision': node['id'], 'reason': 'source-captured-after-known-at'})
        history.append({'id': node['id'], 'sha256': digest(row), 'revision': deepcopy(row),
                        'eligible': identity in eligible,
                        'activeFields': sorted(field for key, field in effects if key == identity and (key, field) not in replaced),
                        'evidence': deepcopy(bundle), 'evidenceBasis': 'pinned-snapshot-observations',
                        'graphHref': '/app/brain.html?node=' + node['id']})
    result = {'protocolVersion': '1.0', 'state': 'conflict' if any(p['state'] == 'conflict' for p in positions) else 'resolved' if positions else 'unknown',
              'decision': decision, 'effectiveAt': effective_at, 'knownAt': known_at, 'snapshotAt': snapshot_at,
              'resolutionScope': 'authorized-recorded-history', 'authorityVerified': False,
              'positions': positions, 'history': history,
              'edges': [deepcopy(e) for e in expected_edges if e['source'] in {n['id'] for n in selected.values()}
                        and (e['target'] in {n['id'] for n in selected.values()} or e['rel'] == 'decision.revision_of')],
              'gaps': gaps, 'priorHistory': 'unknown'}
    if len(json.dumps(result, ensure_ascii=False, allow_nan=False).encode()) > max_bytes:
        return {**unavailable(), 'state': 'limited', 'gaps': ['Decision output limit exceeded; no current position asserted.']}
    return result
