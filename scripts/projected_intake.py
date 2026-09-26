"""Opt-in source-bound text judgment with fresh host approval and lazy body reads."""
from copy import deepcopy

from classified_intake import ClassifiedIntakePlanner
from context_access import ReadBoundary
from context_bundle import encode
from intake_contract import IntakeError, event
from intake_text_projection import ProjectionCatalog, authorize, check, project
from knowledge_policy import fingerprint, timestamp
from local_classifier import bundle_identity, classify, document, pinned, check as classifier_check


class ProjectedIntakePlanner(ClassifiedIntakePlanner):
    PROTOCOL = '3.0'
    SCHEMA = 'projected'
    HISTORY_FORMAT = 'intake-history/v3'
    PROJECTION_FORMAT = 'intake-text-projection/v1'
    RECEIPT_RESERVE = 131072

    def __init__(self, boundary, configuration, *, catalog, projection, authorization, reuse_authorization=None, reuse_configuration_sha256=None, **options):
        super().__init__(boundary, configuration, **options)
        if not isinstance(catalog, ProjectionCatalog) or not callable(authorization):
            raise IntakeError('Projected intake requires a host catalog and current authorization provider')
        if self.PROTOCOL == '4.0' and not callable(reuse_authorization):
            raise IntakeError('Reuse projection requires current cache authorization')
        self.reuse_authorization = reuse_authorization
        check(projection, 'profile')
        self.catalog, self.projection, self.authorization = catalog, deepcopy(projection), authorization
        self._observed_at = timestamp(boundary.now)
        self.profile.update(projection=self.PROJECTION_FORMAT,
                            projectionProfileSha256=fingerprint(projection), catalogSha256=catalog.sha256)
        if self.PROTOCOL == '4.0':
            from intake_text_projection import digest
            self.profile['reuseConfigurationSha256'] = digest(reuse_configuration_sha256)
        self.profile_sha256 = fingerprint(self.profile)
        self.planning_sha256 = fingerprint({'basis': self.basis, 'classifierProfileSha256': self.profile_sha256})

    def _current(self, item, entry, *, previous=None):
        if 'reuse' in entry and self.PROTOCOL != '4.0':
            raise IntakeError('Reused processing requires explicit protocol 4.0')
        boundary, protection = self.authorization()
        if (not isinstance(boundary, ReadBoundary) or boundary.actor != self.boundary.actor
                or boundary.policy.binding['sha256'] != self.basis['policySha256']
                or set(boundary.scopes) != set(self.boundary.scopes)
                or timestamp(boundary.now) < self._observed_at
                or previous and timestamp(boundary.now) < timestamp(previous['authorization']['evaluatedAt'])):
            raise IntakeError('Projected intake current actor, policy or clock changed')
        model = bundle_identity(self.classifier['bundle_sha256'], self.basis['taxonomySha256'])
        classifier, carried = authorize(entry, item, model, boundary, protection,
            retained=previous['protection']['requirements'] if previous else None,
            reuse_authorization=self.reuse_authorization)
        if previous and classifier != previous['classifier']:
            raise IntakeError('Projected classifier resource changed')
        self._observed_at = timestamp(boundary.now)
        return boundary, classifier, carried

    def _abstain(self, history, gaps, reason):
        decision = deepcopy(history['events'][0]['decision'])
        decision['gaps'] = sorted(set(decision['gaps'] + gaps))
        return event({**history, 'events': []}, decision, actor=self.boundary.actor, at=self.boundary.now,
                     reason=reason, mechanism={'tier': 'unassisted', 'rule': None})

    def _fallback(self, history):
        if history['events'][0]['mechanism']['tier'] != 'unassisted':
            return history
        item = history['item']
        entry = self.catalog.entry(item)
        if entry is None:
            return self._abstain(history, ['projection-unavailable'], 'No selected processing representation')
        boundary, classifier, protection = self._current(item, entry)
        representation = self.catalog.representation(item, entry)
        # A slow loader must not freeze an authorization snapshot before admission.
        boundary, classifier, protection = self._current(item, entry)
        source, projection = project(item, representation, entry, self.projection, boundary, classifier, protection, projection_format=self.PROJECTION_FORMAT)
        if 'projection-empty-window' in projection['gaps']:
            return self._abstain(history, projection['gaps'], 'Selected text window is empty')
        # The receipt has its existing 32 KiB reserve. Refuse the call before work
        # if unusually large native coordinates/gaps cannot fit this selected page.
        if len(encode(projection)) > self.RECEIPT_RESERVE - ClassifiedIntakePlanner.RECEIPT_RESERVE:
            return self._abstain(history, ['projection-descriptor-too-large'], 'Projection exceeds selected history bound')
        manifest = document(pinned(self.classifier['bundle'], self.classifier['bundle_sha256'], 4194304))
        classifier_check(manifest, 'bundle')
        if set(self.mapping) != set(manifest['head']['labels']):
            raise IntakeError('Classifier label mapping is incomplete or changed')
        boundary, classifier, protection = self._current(item, entry, previous=projection)
        bindings = deepcopy(boundary.bindings)
        bindings['references'][fingerprint(source)] = entry['sourceResource']
        model_boundary = ReadBoundary(boundary.policy, actor=boundary.actor, now=boundary.now,
                                      scopes=boundary.scopes, bindings=bindings)
        receipt = classify(model_boundary, [source], **self.classifier, log=self.log)
        boundary, classifier, protection = self._current(item, entry, previous=projection)
        # Carry the final observation, retaining the exact submitted bytes and all
        # original protection obligations even if the host relaxed them meanwhile.
        projection['authorization'].update(evaluatedAt=boundary.now,
            bindingsSha256=fingerprint(boundary.bindings), scopes=sorted(boundary.scopes))
        projection['protection'] = protection
        row = receipt['results'][0]
        intent = (self.mapping[row['label']] if row['label'] is not None else
                  {'action': 'review', 'labels': [], 'destinations': [], 'processing': 'none'})
        decision = self.decision(item, intent)
        decision.update(action='review', confidence=row['confidence'])
        decision['gaps'] = sorted(set(decision['gaps'] + row['gaps'] + projection['gaps'] + ['classifier-review-required']))
        mechanism = {'tier': 'classifier', 'rule': None, 'projection': self.PROJECTION_FORMAT,
                     'binarySha256': self.classifier['binary_sha256'], 'bundleSha256': self.classifier['bundle_sha256'],
                     'mappingSha256': fingerprint(self.mapping), 'suggestedAction': intent['action'],
                     'receipt': receipt, 'inputProjection': projection}
        result = event({**history, 'format': self.HISTORY_FORMAT, 'events': []}, decision,
                       actor=self.boundary.actor, at=self.boundary.now,
                       reason='No deterministic rule matched; local extracted-text classifier suggests review',
                       mechanism=mechanism)
        if len(encode(result)) - len(encode(history)) > self.RECEIPT_RESERVE:
            raise IntakeError('Projected history exceeded reserved output space')
        return result

    def plan(self, request):
        result = super().plan(request)
        # Later items may run slow models. Recheck earlier derived labels before
        # returning the whole page, not only immediately after each inference.
        for row in result['results']:
            history = row.get('history', {})
            if history.get('format') == self.HISTORY_FORMAT:
                projection = history['events'][0]['mechanism']['inputProjection']
                _, _, protection = self._current(history['item'], projection['entry'], previous=projection)
                if protection['requirements'] != projection['protection']['requirements']:
                    raise IntakeError('Projected page requires a fresh protection observation')
        return result


class ReuseProjectedIntakePlanner(ProjectedIntakePlanner):
    """Explicit new wire contract; legacy callers retain protocol 3.0."""
    PROTOCOL = '4.0'
    SCHEMA = 'reuse-projected'
    HISTORY_FORMAT = 'intake-history/v4'
    PROJECTION_FORMAT = 'intake-text-projection/v2'
