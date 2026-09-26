"""Opt-in metadata classification after deterministic rules, with durable receipts.

The host selects the engine, mapping, deadline and call budget. Requests cannot
select any of them. Source acquisition and destination delivery remain separate.
"""
from copy import deepcopy
import time

from context_access import ReadBoundary
from context_bundle import encode
from intake import IntakePlanner
from intake_contract import IntakeError, check, event, metadata_input
from knowledge_policy import fingerprint
from local_classifier import bundle_identity, classify, document, execution_profile, pinned, check as classifier_check


class ClassifiedIntakePlanner(IntakePlanner):
    """Fresh request boundary; use the same factory with IntakeAuthority.

    ``mapping`` explicitly maps every model label to a validated intake intent.
    It does not require model labels to be ontology kinds or taxonomy label IDs.
    A fixed metadata projection avoids fetching arbitrary source locators. The
    host must choose a head trained/evaluated for this projection and taxonomy.
    """
    # Conservative space reserved before a call, including the complete bounded
    # receipt and event. A page too small to reserve it performs no inference.
    RECEIPT_RESERVE = 32768
    PROTOCOL = '2.0'
    SCHEMA = True
    HISTORY_FORMAT = 'intake-history/v2'

    def __init__(self, boundary, configuration, *, classifier, mapping, max_model_calls=4, **options):
        super().__init__(boundary, configuration, **options)
        fields = {'binary', 'binary_sha256', 'bundle', 'bundle_sha256', 'taxonomy_sha256', 'timeout_seconds'}
        if (not isinstance(classifier, dict) or set(classifier) not in (fields, fields | {'execution_mode'})
                or classifier['taxonomy_sha256'] != self.basis['taxonomySha256']
                or not isinstance(mapping, dict) or not 2 <= len(mapping) <= 32
                or type(max_model_calls) is not int or not 0 <= max_model_calls <= 64):
            raise IntakeError('Invalid classified intake host profile')
        execution_profile(classifier.get('execution_mode', 'process'), classifier['timeout_seconds'])
        for intent in mapping.values():
            self.validate_intent(intent)
        self.classifier, self.mapping = deepcopy(classifier), deepcopy(mapping)
        self.max_model_calls = max_model_calls
        self.profile = {'projection': 'intake-metadata/v1', 'binarySha256': classifier['binary_sha256'],
                        'bundleSha256': classifier['bundle_sha256'], 'taxonomySha256': classifier['taxonomy_sha256'],
                        'mappingSha256': fingerprint(mapping), 'maxModelCalls': max_model_calls,
                        'timeoutSeconds': classifier['timeout_seconds']}
        if classifier.get('execution_mode') == 'embedded':
            self.profile['executionMode'] = 'embedded'
        self.profile_sha256 = fingerprint(self.profile)
        self.planning_sha256 = fingerprint({'basis': self.basis, 'classifierProfileSha256': self.profile_sha256})

    def _model_boundary(self, item):
        boundary = self.boundary
        model = bundle_identity(self.classifier['bundle_sha256'], self.basis['taxonomySha256'])
        if not self.authorized(item) or not boundary.permits('references', model):
            raise IntakeError('Intake source or classifier unavailable')
        resource = boundary.bindings['references'][fingerprint(item)]
        model_resource = boundary.bindings['references'][model]
        # Persisting a derived label must not release a differently scoped model.
        # Cross-scope model publication needs the explicit promotion adapter.
        if boundary.policy.resources[resource]['scope'] != boundary.policy.resources[model_resource]['scope']:
            raise IntakeError('Cross-scope model-derived history requires explicit publication')
        bindings = deepcopy(boundary.bindings)
        derived = metadata_input(item)
        bindings['references'][fingerprint(derived)] = resource
        return ReadBoundary(boundary.policy, actor=boundary.actor, now=boundary.now,
                            scopes=boundary.scopes, bindings=bindings), derived

    def _fallback(self, history):
        if history['events'][0]['mechanism']['tier'] != 'unassisted':
            return history
        boundary, source = self._model_boundary(history['item'])
        if len(source['text'].encode('utf-8')) > 16384:
            # Retain a normal deterministic abstention with an explicit reason.
            decision = deepcopy(history['events'][0]['decision'])
            decision['gaps'].append('classifier-input-too-large')
            empty = {**history, 'events': []}
            return event(empty, decision, actor=boundary.actor, at=boundary.now,
                         reason='Metadata exceeds the selected classifier input limit',
                         mechanism={'tier': 'unassisted', 'rule': None})
        manifest = document(pinned(self.classifier['bundle'], self.classifier['bundle_sha256'], 4194304))
        classifier_check(manifest, 'bundle')
        if set(self.mapping) != set(manifest['head']['labels']):
            raise IntakeError('Classifier label mapping is incomplete or changed')
        receipt = classify(boundary, [source], **self.classifier, log=self.log)
        row = receipt['results'][0]
        intent = (self.mapping[row['label']] if row['label'] is not None else
                  {'action': 'review', 'labels': [], 'destinations': [], 'processing': 'none'})
        decision = self.decision(history['item'], intent)
        decision.update(action='review', confidence=row['confidence'])
        decision['gaps'] = sorted(set(decision['gaps'] + row['gaps'] + ['classifier-review-required']))
        mechanism = {'tier': 'classifier', 'rule': None, 'projection': 'intake-metadata/v1',
                     'binarySha256': self.classifier['binary_sha256'],
                     'bundleSha256': self.classifier['bundle_sha256'], 'mappingSha256': fingerprint(self.mapping),
                     'suggestedAction': intent['action'], 'receipt': receipt}
        result = event({**history, 'format': 'intake-history/v2', 'events': []}, decision,
                       actor=boundary.actor, at=boundary.now,
                       reason='No deterministic rule matched; local metadata classifier suggests review',
                       mechanism=mechanism)
        if len(encode(result)) - len(encode(history)) > self.RECEIPT_RESERVE:
            # An unexpected contract expansion fails closed. The classifier audit
            # still retains admission and verified execution usage.
            raise IntakeError('Classifier history exceeded reserved output space')
        return result

    def history(self, item):
        history = super().history(item)
        if self.max_model_calls == 0:
            return history
        return self._fallback(history)

    def plan(self, request):
        """Bounded v2 page. Calls already made are accounted even at byte truncation.

        v1 remains the deterministic-only protocol. The call cap is per page,
        not a shared durable quota. Retrying a page may repeat inference; audit
        reservations record every invocation. Tokens are unknown, never zeroed.
        """
        started = time.perf_counter_ns()
        check(request, 'request', classified=self.SCHEMA)
        if (request['planningSha256'] not in (None, self.planning_sha256)
                or request['offset'] and request['planningSha256'] != self.planning_sha256):
            raise IntakeError('Classified intake continuation basis changed')
        if len(encode(request)) > min(self.limits['maxInputBytes'], request['budget']['maxInputBytes']):
            raise IntakeError('Classified intake input budget exceeded')
        deterministic = IntakePlanner(self.boundary, self.config, completed=self.completed,
                                      completion_lookup=self.completion_lookup, limits=self.limits, log=self.log)
        source_request = {key: value for key, value in request.items() if key != 'planningSha256'}
        result = deterministic.plan({**source_request, 'protocolVersion': '1.0'})
        pending = result['results']
        result.update(protocolVersion=self.PROTOCOL, results=[], classifierProfileSha256=self.profile_sha256,
                      planningSha256=self.planning_sha256)
        reserve = {**result, 'nextOffset': len(request['items']),
                   'truncation': ['maxItems', 'maxBytes', 'maxModelCalls'],
                   'usage': {'modelCalls': 64, 'inputTokens': None, 'outputTokens': None,
                             'elapsedMicros': 9007199254740991}}
        used, calls = len(encode(reserve)), 0
        if used > result['limits']['maxOutputBytes']:
            raise IntakeError('Classified intake output budget cannot hold envelope')
        for index, row in enumerate(pending, request['offset']):
            candidate = (row['status'] == 'planned' and
                         row['history']['events'][0]['mechanism']['tier'] == 'unassisted')
            # With zero selected calls classification is disabled; retain the
            # deterministic abstention instead of producing a stuck cursor.
            candidate = candidate and self.max_model_calls > 0
            if candidate and calls == self.max_model_calls:
                result.update(nextOffset=index, truncation=['maxModelCalls'])
                break
            space = len(encode(row)) + bool(result['results'])
            if used + space + (self.RECEIPT_RESERVE if candidate else 0) > result['limits']['maxOutputBytes']:
                result.update(nextOffset=index, truncation=['maxBytes'])
                break
            if candidate:
                history = self._fallback(row['history'])
                row = {**row, 'history': history}
                if history['format'] == self.HISTORY_FORMAT:
                    calls += history['events'][0]['mechanism']['receipt']['usage']['embeddingCalls']
            used += len(encode(row)) + bool(result['results'])
            result['results'].append(row)
        result['usage'] = {'modelCalls': calls, 'inputTokens': None if calls else 0,
                           'outputTokens': None if calls else 0,
                           'elapsedMicros': min(9007199254740991, (time.perf_counter_ns() - started) // 1000)}
        check(result, 'result', classified=self.SCHEMA)
        self.log('intake.classified', self.boundary.actor, result['inputSha256'],
                 {'profileSha256': self.profile_sha256, 'modelCalls': calls,
                  'processed': len(result['results']), 'nextOffset': result['nextOffset']})
        return result
