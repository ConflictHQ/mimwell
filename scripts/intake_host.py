"""Shared pinned host construction for deterministic and classified intake planners."""
import datetime as dt
from pathlib import Path
import time

from brain_federation import fields
from context_host import _read, load_boundary, read_pinned
from intake import IntakePlanner
from knowledge_policy import fingerprint, local_path, timestamp


def load_planner(root, config_path, *, actor, now, log):
    started = time.monotonic()
    root = Path(root)
    if root.is_symlink():
        raise ValueError('Intake root cannot be a symlink')
    config = _read(root, config_path)
    version = config.get('protocolVersion')
    required = ('protocolVersion', 'policy', 'bindings', 'scopes', 'intake', 'completed', 'limits')
    fields(config, required + (('classifier',) if version in ('2.0', '3.0', '4.0') else ()) +
           (('projection',) if version in ('3.0', '4.0') else ()))
    if version not in ('1.0', '2.0', '3.0', '4.0'):
        raise ValueError('Unsupported intake host')
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    options = {'completed': read_pinned(root, config['completed']), 'limits': config['limits'], 'log': log}
    planner = IntakePlanner
    if version in ('2.0', '3.0', '4.0'):
        from classified_intake import ClassifiedIntakePlanner
        profile = read_pinned(root, config['classifier'])
        fields(profile, ('binary', 'bundle', 'taxonomySha256', 'timeoutSeconds', 'maxModelCalls', 'mapping')
               + (('executionMode',) if isinstance(profile, dict) and 'executionMode' in profile else ()))
        for artifact in ('binary', 'bundle'):
            fields(profile[artifact], ('path', 'sha256'))
        options.update(classifier={
            'binary': root.resolve() / local_path(profile['binary']['path']),
            'binary_sha256': profile['binary']['sha256'],
            'bundle': root.resolve() / local_path(profile['bundle']['path']),
            'bundle_sha256': profile['bundle']['sha256'],
            'taxonomy_sha256': profile['taxonomySha256'], 'timeout_seconds': profile['timeoutSeconds']},
            mapping=profile['mapping'], max_model_calls=profile['maxModelCalls'])
        if 'executionMode' in profile:
            options['classifier']['execution_mode'] = profile['executionMode']
        planner = ClassifiedIntakePlanner
    if version in ('3.0', '4.0'):
        from projected_intake import ProjectedIntakePlanner
        from intake_text_projection import ProjectionCatalog, digest
        from federation_protection import SourceProtection
        projection = read_pinned(root, config['projection'])
        fields(projection, ('profile', 'catalog', 'protection') + (('reuse',) if version == '4.0' else ()))
        catalog = read_pinned(root, projection['catalog'])
        fields(catalog, ('entries', 'representations'))
        if (not isinstance(catalog['entries'], dict) or not isinstance(catalog['representations'], dict)
                or set(catalog['entries']) != set(catalog['representations'])):
            raise ValueError('Projection catalog requires exact host body registrations')
        for value in catalog['representations'].values():
            fields(value, ('path', 'sha256'))
            local_path(value['path'])
            digest(value['sha256'])
        # Independent host pins are checked before lazy body I/O. The catalog's
        # semantic digest binds headers/representation bytes, not incidental paths.
        selected = ProjectionCatalog(catalog['entries'], expected_sha256=fingerprint(catalog['entries']),
            load=lambda identity: read_pinned(root, catalog['representations'][identity]))
        initial = timestamp(now)
        def authorization():
            # --now supplies a trusted initial time, never a frozen grant through
            # slow body/model work. Reload current protected files at each gate.
            current_time = (initial + dt.timedelta(seconds=time.monotonic() - started)).isoformat(timespec='milliseconds')
            if _read(root, config_path) != config or read_pinned(root, config['projection']) != projection:
                raise ValueError('Projected intake host selection changed during execution')
            current, _ = load_boundary(root, config, actor=actor, now=current_time)
            protection = SourceProtection(read_pinned(root, projection['protection']), resources=current.policy.resources)
            return current, protection
        options.update(catalog=selected, projection=projection['profile'], authorization=authorization)
        planner = ProjectedIntakePlanner
        if version == '4.0':
            from intake_processing_cache import ProcessingCache, validator as cache_validator
            from projected_intake import ReuseProjectedIntakePlanner
            reuse = read_pinned(root, projection['reuse'])
            fields(reuse, ('cache', 'registrations'))
            fields(reuse['cache'], ('path', 'configSha256'))
            cache_path = root.resolve() / local_path(reuse['cache']['path'])
            digest(reuse['cache']['configSha256'])
            registrations = read_pinned(root, reuse['registrations'])
            if not isinstance(registrations, dict) or not 1 <= len(registrations) <= 10000:
                raise ValueError('Bounded independent processing registrations required')
            for identity, registration in registrations.items():
                digest(identity)
                fields(registration, ('original',))
                original = registration['original']
                if original is not None and (not cache_validator('header').is_valid(original)
                                             or original['itemSha256'] != identity):
                    raise ValueError('Independent processing registration differs from original')
            def current_source(identity, *, actor, at):
                if (_read(root, config_path) != config or read_pinned(root, config['projection']) != projection
                        or read_pinned(root, projection['reuse']) != reuse
                        or read_pinned(root, reuse['registrations']) != registrations or identity not in registrations):
                    raise ValueError('Processing reuse host selection changed')
                current, _ = load_boundary(root, config, actor=actor, now=at)
                protection = SourceProtection(read_pinned(root, projection['protection']), resources=current.policy.resources)
                return current, protection, registrations[identity]['original']
            cache = ProcessingCache(cache_path, expected_config_sha256=reuse['cache']['configSha256'],
                                    authorization=current_source)
            options.update(reuse_authorization=cache.authorize_selection,
                           reuse_configuration_sha256=fingerprint(reuse))
            planner = ReuseProjectedIntakePlanner
    selected = planner(boundary, read_pinned(root, config['intake']), **options)
    if version == '4.0':
        # The same host-selected cache also supplies the native processed-write
        # gate. It is never chosen from a submitted processing receipt.
        selected.processing_reuse_authorization = cache.authorize
    return selected
