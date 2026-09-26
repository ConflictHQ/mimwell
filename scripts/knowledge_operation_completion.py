"""Host-selected completion observations over the existing rebuildable index."""
from contextlib import closing
from copy import deepcopy
from functools import partial

from intake_completion import CompletionIndex, CompletionUnavailable
from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError
from local_classifier import bundle_identity
from maintenance_audit import audit, operation as log_operation


def revalidate_history(planner, history):
    if planner.basis != history['basis'] or not planner.authorized(history['item']):
        raise StoreError('Planned intake source or basis changed')
    item, event = history['item'], history['events'][-1]
    mechanism = event['mechanism']
    if mechanism['tier'] == 'classifier':
        identity = bundle_identity(planner.classifier['bundle_sha256'], planner.basis['taxonomySha256'])
        if not planner.boundary.permits('references', identity):
            raise StoreError('Planned intake model unavailable')
        if 'inputProjection' in mechanism:
            planner._current(item, planner.catalog.entry(item), previous=mechanism['inputProjection'])
    for row in event['decision']['destinations']:
        destination = planner.destinations[row['id']]
        if not planner.boundary.permits_resource(destination['resource'], destination['id']):
            raise StoreError('Planned intake destination unavailable')
        if row['status'] in ('proposed', 'already-ingested'):
            request = {'id': 'intake-proposal-check', 'resource': destination['resource'], 'record': item['id'],
                       'mutation': 'create', 'expectedRevision': None, 'reason': 'Plan source intake',
                       'evidence': ['intake:' + fingerprint(item)], 'sourceResource': None}
            context = {'actor': planner.boundary.actor, 'now': planner.boundary.now,
                       'operation': 'propose', 'currentRevision': None}
            if not planner.boundary.policy.evaluate(request, context)['allowed']:
                raise StoreError('Planned intake proposal permission changed')


def run_completion(adapter, request, *, actor, clock, max_response_bytes):
    from knowledge_operations import private_path, response_bytes

    registration = adapter.registration.get('completion')
    if registration is None:
        raise StoreError('Native completion index registration required')
    root, store = adapter.root, adapter.store
    path = private_path(root, registration['index'])
    if path.samefile(store.path):
        raise StoreError('Completion index must be distinct from its authority')
    identity = (path.stat().st_dev, path.stat().st_ino)

    def guard():
        adapter.guard()
        current = private_path(root, registration['index']).stat()
        if (current.st_dev, current.st_ino) != identity:
            raise StoreError('Completion index file changed')

    guard()
    at = clock()
    with closing(CompletionIndex(path, store, adapter.registration['destinations'])) as index:
        if request['operation'] == 'intake.completion-refresh':
            args = request['arguments']
            native = index.refresh(max_events=args['maxEvents'], max_bytes=args['maxBytes'])
        else:
            observations = []
            with audit(root) as journal:
                planner = adapter.planner(actor, at, partial(log_operation, journal))
                if planner.completed:
                    raise StoreError('Select native completion instead of a static completion map')

                def lookup(selected, item, destination, processing, labels):
                    args = deepcopy((item, destination, processing, labels))
                    try:
                        value = index.lookup(selected, *args)
                    except CompletionUnavailable:
                        observations.append((args, False, None))
                        raise
                    observations.append((args, True, value))
                    return value

                planner.completion_lookup = lookup
                native = planner.plan(request['arguments']['request'])
            guard()
            final = adapter.planner(actor, clock(), adapter.no_inference)
            if (final.basis != planner.basis or final.completed
                    or getattr(final, 'planning_sha256', None) != getattr(planner, 'planning_sha256', None)):
                raise StoreError('Completion planning selection changed')
            for row in native['results']:
                if row['status'] == 'planned':
                    revalidate_history(final, row['history'])
            for args, available, expected in observations:
                try:
                    actual = index.lookup(final, *args)
                except CompletionUnavailable:
                    if available:
                        raise StoreError('Completion observation became unavailable') from None
                else:
                    if not available or actual != expected:
                        raise StoreError('Completion observation changed before release')
        guard()
        final_at = clock()
        if timestamp(final_at) < timestamp(at):
            raise StoreError('Completion operation clock moved backwards')
        adapter.revalidate(final_at)
        raw = response_bytes(request, store, native, actor, at, final_at, max_response_bytes)
        guard()
        return raw
