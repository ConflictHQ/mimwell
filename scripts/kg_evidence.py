"""Preserve producer observations while legacy KG records deduplicate.

These are source claims, not authorization or independently grounded evidence.
Identified source records continue through kg_identity's stricter reconciliation.
"""
from __future__ import annotations

import copy
import json


def unique_rows(rows):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError('graph evidence collections must contain objects')
    result, seen = [], set()
    for row in rows:
        key = json.dumps(row, sort_keys=True, allow_nan=False)
        if key not in seen:
            result.append(copy.deepcopy(row))
            seen.add(key)
    return result


def edge_claims(record, *, force=False):
    """Accept native extraction rows as well as conflict-kg props observations."""
    result = copy.deepcopy(record)
    props = result.setdefault('props', {})
    if not isinstance(props, dict):
        raise ValueError('graph props must be an object')
    if 'evidence' in result or (force and 'observations' not in props):
        observation = {'raw_type': result.get('type'),
                       'confidence': result.get('confidence', props.get('confidence'))}
        for key in ('evidence', 'content_source', 'timestamp'):
            if key in result or key in props:
                observation[key] = result.get(key, props.get(key))
        props['observations'] = unique_rows(props.get('observations', []) + [observation])
        for key in ('evidence', 'content_source', 'timestamp', 'confidence'):
            if key in result:
                if key in props and props[key] != result[key]:
                    raise ValueError(f'graph property collides with props: {key}')
                props[key] = result.pop(key)
    if 'observations' in props:
        props['observations'] = unique_rows(props['observations'])
    if not props:
        result.pop('props')
    return result


def merge_claims(target, incoming):
    """Union evidence collections without borrowing another observation's data."""
    if ('source' in target and 'target' in target and
            ('observations' in target.get('props', {}) or
             'observations' in incoming.get('props', {}))):
        retained = edge_claims(target, force=True)
        target.clear()
        target.update(retained)
        incoming = edge_claims(incoming, force=True)
    for key in ('occurrences', 'descriptions'):
        if key in incoming:
            rows = target.setdefault(key, [])
            if not isinstance(rows, list) or not isinstance(incoming[key], list):
                raise ValueError(f'graph {key} must be an array')
            for item in incoming[key]:
                if item not in rows:
                    rows.append(copy.deepcopy(item))
    target_props = target.setdefault('props', {})
    incoming_props = incoming.get('props', {})
    if not isinstance(target_props, dict) or not isinstance(incoming_props, dict):
        raise ValueError('graph props must be an object')
    for key, value in incoming_props.items():
        if key in ('occurrences', 'observations'):
            target_props[key] = unique_rows(target_props.get(key, []) + value)
        elif key in ('descriptions', 'sources', 'raw_types'):
            if not isinstance(value, list) or not isinstance(target_props.get(key, []), list):
                raise ValueError(f'graph {key} must be an array')
            values = target_props.setdefault(key, [])
            for item in value:
                if item not in values:
                    values.append(copy.deepcopy(item))
        elif key not in target_props:
            target_props[key] = copy.deepcopy(value)
    if 'occurrences' in target_props and 'occurrences' in target:
        target_props['occurrences'] = unique_rows(
            target_props['occurrences'] + target.pop('occurrences'))
    if 'observations' in target_props:
        observations = target_props['observations']
        confidence = [row.get('confidence') for row in observations]
        target_props['confidence'] = (
            confidence[0] if confidence and all(c == confidence[0] for c in confidence) else None
        )
    evidence_rows = target_props.get('observations')
    if evidence_rows is None:
        evidence_rows = target_props.get('occurrences', target.get('occurrences', []))
    if ('evidence_status' in target_props or any('evidence' in row for row in evidence_rows)):
        qualified = [isinstance(row.get('evidence'), dict) and
                     bool(row['evidence'].get('source_revision')) for row in evidence_rows]
        target_props['evidence_status'] = (
            'source_qualified' if qualified and all(qualified)
            else 'mixed' if any(qualified) else 'legacy_unqualified'
        )
    if not target_props:
        target.pop('props', None)
