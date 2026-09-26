"""Intake wire validation and canonical history invariants, independent of the planner."""
from copy import deepcopy
from functools import lru_cache
import json
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from knowledge_policy import fingerprint, timestamp


class IntakeError(ValueError):
    pass


@lru_cache(maxsize=None)
def validator(name, classified=False):
    filename = ('projected-intake-v2.schema.json' if classified == 'reuse-projected' else
                'projected-intake.schema.json' if classified == 'projected' else
                'classified-intake.schema.json' if classified else 'intake.schema.json')
    root = Path(__file__).resolve().parents[1] / 'schemas'
    schema = json.loads((root / filename).read_text())
    registry = Registry()
    if classified:
        for dependency in ('intake.schema.json', 'classifier.schema.json') + (
                ('intake-text-projection.schema.json',) if classified == 'projected' else
                ('intake-text-projection.schema.json', 'intake-processing-reuse.schema.json',
                 'intake-reuse-selection.schema.json', 'intake-text-projection-v2.schema.json')
                if classified == 'reuse-projected' else ()):
            document = json.loads((root / dependency).read_text())
            registry = registry.with_resource(document['$id'], Resource.from_contents(document))
    return Draft202012Validator({'$ref': '#/$defs/' + name, '$defs': schema['$defs']}, registry=registry)


def check(value, name, *, classified=False):
    if not validator(name, classified).is_valid(value):
        raise IntakeError('Invalid intake ' + name)


def validate_history(history):
    version = history.get('format') if isinstance(history, dict) else None
    classified = ('reuse-projected' if version == 'intake-history/v4' else
                  'projected' if version == 'intake-history/v3' else version == 'intake-history/v2')
    check(history, 'history', classified=classified)
    previous = None
    for index, event in enumerate(history['events']):
        payload = {k: v for k, v in event.items() if k != 'id'}
        if (event['id'] != fingerprint({'item': history['item'], 'basis': history['basis'], 'event': payload})
                or event['previous'] != previous
                or event['type'] != ('correction' if index else 'proposal')
                or (index and event['mechanism'] != {'tier': 'correction', 'rule': None})
                or (not index and event['mechanism']['tier'] not in (
                    ('classifier',) if classified else ('rules', 'unassisted')))
                or (event['mechanism']['tier'] != 'rules' and event['mechanism']['rule'] is not None)
                or (event['mechanism']['tier'] == 'rules' and event['mechanism']['rule'] is None)):
            raise IntakeError('Intake history chain changed')
        if event['mechanism']['tier'] == 'classifier':
            validate_classification(history, event)
        elif event['decision']['confidence'] is not None:
            raise IntakeError('Only a classifier receipt can declare confidence')
        at = timestamp(event['at'])
        if index and at < timestamp(history['events'][index - 1]['at']):
            raise IntakeError('Intake event time moved backwards')
        previous = event['id']


def metadata_input(item):
    """Fixed, versioned projection of already authorized metadata, never source I/O."""
    from context_bundle import encode
    return {'id': item['id'], 'text': encode({'mediaType': item['source']['mediaType'],
                                           'metadata': item['metadata']}).decode('utf-8')}


def validate_classification(history, event):
    """Receipt consistency, not proof of authentic inference or fitted calibration."""
    import hashlib
    import math
    from context_bundle import encode
    mechanism, decision = event['mechanism'], event['decision']
    receipt = mechanism['receipt']
    if history['format'] in ('intake-history/v3', 'intake-history/v4'):
        from intake_text_projection import validate_descriptor
        from local_classifier import bundle_identity
        projection = mechanism['inputProjection']
        validate_descriptor(projection, history['item'])
        authorization = projection['authorization']
        if (authorization['principal'] != event['actor']
                or authorization['policySha256'] != history['basis']['policySha256']
                or timestamp(authorization['evaluatedAt']) < timestamp(event['at'])
                or projection['classifier']['identity'] != bundle_identity(
                    mechanism['bundleSha256'], history['basis']['taxonomySha256'])
                or not set(projection['gaps']).issubset(decision['gaps'])
                or not projection['textBytes'] or 'projection-empty-window' in projection['gaps']):
            raise IntakeError('Projected classifier lineage or authorization changed')
        input_sha, input_bytes = projection['requestSha256'], projection['inputBytes']
        input_id, text_bytes = projection['modelInputId'], projection['textBytes']
    else:
        source = metadata_input(history['item'])
        raw = encode({'protocolVersion': '1.0', 'items': [source]})
        input_sha, input_bytes = hashlib.sha256(raw).hexdigest(), len(raw)
        input_id, text_bytes = source['id'], len(source['text'].encode('utf-8'))
    usage, rows, labels = receipt['usage'], receipt['results'], receipt['labels']
    calibration = receipt['calibration']
    if (not math.isfinite(calibration['temperature'])
            or text_bytes > 16384
            or calibration['method'] == 'none' and
            (calibration['temperature'] != 1 or calibration['evidenceSha256'] is not None)
            or calibration['method'] == 'temperature' and calibration['evidenceSha256'] is None):
        raise IntakeError('Classifier calibration declaration changed')
    if (receipt['bundleSha256'] != mechanism['bundleSha256']
            or receipt['taxonomySha256'] != history['basis']['taxonomySha256']
            or receipt['inputSha256'] != input_sha
            or len(rows) != 1 or rows[0]['id'] != input_id
            or usage['classifiedItems'] != 1 or usage['embeddingCalls'] != 1
            or usage['inputBytes'] != input_bytes or decision['action'] != 'review'
            or 'classifier-review-required' not in decision['gaps']):
        raise IntakeError('Classifier history basis or review boundary changed')
    row = rows[0]
    scores, selected = row['probabilities'], row['label']
    if selected is None:
        if (scores or row['confidence'] is not None or row['gaps'] != ['empty-embedding']
                or mechanism['suggestedAction'] != 'review' or decision['labels'] or decision['kinds']
                or decision['destinations'] or decision['processing'] != 'none'):
            raise IntakeError('Classifier abstention changed')
    else:
        calibrated = receipt['calibration']['method'] == 'temperature'
        if (len(scores) != len(labels) or any(not math.isfinite(v) for v in scores)
                or abs(sum(scores) - 1) > 1e-8 or selected != labels[max(range(len(scores)), key=scores.__getitem__)]
                or row['confidence'] != (max(scores) if calibrated else None)
                or row['gaps'] != ([] if calibrated else ['uncalibrated'])):
            raise IntakeError('Classifier score interpretation changed')
    if decision['confidence'] != row['confidence'] or not set(row['gaps']).issubset(decision['gaps']):
        raise IntakeError('Classifier confidence or gaps changed')


def event(history, decision, *, actor, at, reason, mechanism):
    payload = {'previous': history['events'][-1]['id'] if history['events'] else None,
               'type': 'correction' if history['events'] else 'proposal', 'actor': actor, 'at': at,
               'decision': deepcopy(decision), 'reason': reason, 'mechanism': deepcopy(mechanism)}
    result = deepcopy(history)
    result['events'].append({'id': fingerprint({'item': history['item'], 'basis': history['basis'], 'event': payload}), **payload})
    validate_history(result)
    return result


def history_change(before, after, *, actor, at):
    """Canonical writer invariant for an adopted history, including generic writes."""
    old = (before or {}).get('content', {}).get('data', {}).get('intakeHistory')
    new = after.get('content', {}).get('data', {}).get('intakeHistory')
    if old is None and new is None:
        return
    if new is None:
        raise IntakeError('A correction cannot erase intake history')
    validate_history(new)
    if old is not None:
        validate_history(old)
        if old == new:
            return
        if (old['format'] != new['format'] or old['item'] != new['item'] or old['basis'] != new['basis']
                or new['events'][:-1] != old['events']):
            raise IntakeError('Intake corrections must append one event without rewriting history')
    elif len(new['events']) != 1:
        raise IntakeError('History import requires an explicit import boundary')
    if new['events'][-1]['actor'] != actor or timestamp(new['events'][-1]['at']) != timestamp(at):
        raise IntakeError('New intake event must bind the authenticated proposer and proposal time')
