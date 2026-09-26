"""Read-only inspection beside the exact authorized context wire payload (#91).

This is a presentation adapter, not a retriever, canonical writer or permission
receipt. The host must obtain bytes through the current context authorization
boundary. It never adds records, evidence, findings or source reads to that view.
"""
from copy import deepcopy
import hashlib

from context_bundle import ContextError, encode, validate_request
from context_host import decode

MAX_CONTEXT_BYTES = 1024 * 1024
MAX_INSPECTION_BYTES = 4 * 1024 * 1024


def inspect_bytes(raw, *, max_bytes=MAX_INSPECTION_BYTES):
    """Summarize actual canonical compiler bytes without re-encoding the payload."""
    if (not isinstance(raw, bytes) or not raw or len(raw) > MAX_CONTEXT_BYTES or
            type(max_bytes) is not int or not 1 <= max_bytes <= MAX_INSPECTION_BYTES):
        raise ContextError('Invalid inspection byte limit or context')
    context = decode(raw)
    if not isinstance(context, dict) or encode(context) != raw:
        raise ContextError('Inspection requires canonical context wire bytes')
    required = {'protocolVersion', 'request', 'authorization', 'nodes', 'edges',
                'references', 'groups', 'gaps', 'truncation', 'coverage'}
    if (set(context) not in (required, required | {'projectionFreshness'}) or
            context['protocolVersion'] != '1.0'):
        raise ContextError('Unsupported context envelope')
    validate_request(context['request'])
    for key in ('nodes', 'edges', 'references', 'gaps', 'truncation'):
        if not isinstance(context[key], list):
            raise ContextError('Invalid context observation')
    if (any(not isinstance(row, dict) for key in ('nodes', 'edges', 'references', 'gaps') for row in context[key]) or
            any(not isinstance(item, str) for item in context['truncation']) or
            any(not isinstance(context[key], dict) for key in ('authorization', 'coverage', 'groups'))):
        raise ContextError('Invalid context observation shape')
    # The compiler already emits declared contradictions and evidence conflicts.
    # No inference over hidden inputs or a second semantic classifier is run here.
    conflicts = [deepcopy(gap) for gap in context['gaps'] if gap.get('state') == 'contradiction']
    evidence_records = sum(bool(row.get('evidence')) for row in context['nodes'] + context['edges'])
    digest = hashlib.sha256(raw).hexdigest()
    summary = {
        'contextSha256': digest,
        'basis': deepcopy(context['request']),
        'authorization': deepcopy(context['authorization']),
        'counts': {'nodes': len(context['nodes']), 'edges': len(context['edges']),
                   'references': len(context['references']), 'localRecordsWithEvidence': evidence_records,
                   'resolvedReferences': sum(row.get('status') == 'resolved' for row in context['references']),
                   'referencesWithEvidence': sum(bool(row.get('record', {}).get('evidence')) for row in context['references'] if row.get('status') == 'resolved')},
        'gaps': deepcopy(context['gaps']), 'conflicts': conflicts,
        'conflictAssessment': 'Declared and evidence conflicts in this selected context only; semantic completeness not assessed.',
        'freshness': deepcopy(context.get('projectionFreshness', {
            'scope': 'selected-context', 'state': 'unknown',
            'reason': 'No projection freshness assessment supplied; asOf is a knowledge basis, not proof of freshness.'})),
        'coverage': deepcopy(context['coverage']), 'truncation': deepcopy(context['truncation']),
        'consumption': 'This is a captured authorized preview, not a continuing access grant. Request fresh context before a later operation.',
    }
    result = {'format': 'context-inspection/v1',
              'context': {'encoding': 'utf-8', 'mediaType': 'application/json', 'sha256': digest,
                          'bytes': len(raw), 'payload': raw.decode('utf-8')},
              'summary': summary}
    if len(encode(result)) > max_bytes:
        raise ContextError('Inspection response exceeds its byte budget')
    return result
