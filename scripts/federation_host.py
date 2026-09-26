"""Declarative federation loading; all settings are operator-owned pins."""
from pathlib import Path

from brain_federation import fields, strings, text
from context_bundle import ContextError
from context_host import load_boundary, read_pinned
from federation_discovery_host import DISCOVERY_FIELDS, load_view
from context_references import ReferencePlan
from federation_http import RemoteRecordSource
from federation_resolution import FederationResolver, LocalRecordSource, load_code_records
from federation_store import SQLiteRecordSource
from knowledge_policy import local_path
from ontology import Registry
from principals import PrincipalError, Principals


def source_root(root, relative):
    """Source roots are local mounts inside the operator-selected host root."""
    if relative is None:
        return root
    text(relative)
    path = local_path(relative)
    if any((root / Path(*path.parts[:i])).is_symlink() for i in range(1, len(path.parts) + 1)):
        raise ContextError("Federation source roots cannot follow symlinks")
    return root / path


def consumer_mapping(mapping, actor, principals):
    """This consumer's entry in an operator mapping (#212).

    A key is the raw consumer credential actor, or, with a pinned person
    register, any identity (`person:<slug>`, `oidc:<issuer>#<subject>`) that
    resolves to the same principal as `consumer:<actor>`. Keys that match with
    different values refuse; no match is None, which callers deny.
    """
    principal = principals.resolve("consumer:" + actor) if principals is not None else None
    values = []
    for key, value in mapping.items():
        if (key == actor or (principal is not None and principals.resolve(key) == principal)) and value not in values:
            values.append(value)
    if len(values) > 1:
        raise ContextError("Consumer resolves to conflicting source mappings")
    return values[0] if values else None


def load_resolver(root, config, *, boundary, selection=None, capability="resolve", access_log=None):
    config_fields = ("protocolVersion", "catalog", "inventory", "manifests", "discoveryBindings",
                     "reviewedSubjects", "routes", "sources")
    for optional in ("remoteSources", "people"):
        if isinstance(config, dict) and optional in config:
            config_fields += (optional,)
    fields(config, config_fields)
    if config["protocolVersion"] != "1.0":
        raise ContextError("Unsupported federation host configuration")
    if not isinstance(config["manifests"], dict) or not isinstance(config["sources"], list):
        raise ContextError("Invalid federation host manifests or sources")
    root = Path(root)
    principals = None
    if "people" in config:
        try:
            principals = Principals(read_pinned(root, config["people"]))
        except PrincipalError as exc:
            raise ContextError("Invalid federation person register") from exc
    view = load_view(root, {key: config[key] for key in DISCOVERY_FIELDS}, boundary=boundary)
    sources, handles, realms, protection_mounts, served = {}, set(), set(), {}, {}
    for settings in config["sources"]:
        fields(settings, ("handle", "participant", "realm", "authority", "root", "principals",
                          "policy", "scopes", "bindings", "publications", "records") +
               (('protection',) if 'protection' in settings else ()))
        for key in ("handle", "participant", "realm", "authority"):
            text(settings[key])
        strings(settings["scopes"])
        if not isinstance(settings["principals"], dict):
            raise ContextError("Source principals require an explicit consumer mapping")
        for consumer, principal in settings["principals"].items():
            text(consumer)
            text(principal)
        key = (settings["participant"], settings["realm"])
        if settings["handle"] in handles or key in realms:
            raise ContextError("Duplicate federation source handle or realm")
        handles.add(settings["handle"])
        realms.add(key)
        if selection is not None and key not in selection:
            continue
        descriptor = view.realm(*key)
        # Discovery permission is established before opening source policy,
        # knowledge, publication files, or code. Offline peers require no mount.
        if descriptor is None or descriptor["transport"] != "local":
            continue
        if selection is not None and descriptor['revision'] != selection[key]:
            continue
        if descriptor["handle"] != settings["handle"] or descriptor["authority"] != settings["authority"]:
            raise ContextError("Configured source disagrees with federation discovery")
        if descriptor["resolverVersion"] != "1.0" or descriptor["addressContract"] != "1.0" or "resolve" not in descriptor["capabilities"] or capability not in descriptor["capabilities"]:
            continue
        actor = consumer_mapping(settings["principals"], boundary.actor, principals)
        if actor is None:
            raise ContextError("No authenticated source principal mapping for this consumer")
        base = source_root(root, settings["root"])
        source_boundary, ontology = load_boundary(base, settings, actor=actor, now=boundary.now)
        protection = None
        if 'protection' in settings:
            from federation_protection import SourceProtection, mount
            fields(settings['protection'], ('policy', 'selected'))
            protection = read_pinned(base, settings['protection']['policy'])
            declared = SourceProtection(protection, resources=source_boundary.policy.resources)
            protection_mounts[key] = mount({'policySha256': declared.sha256,
                                             'selected': settings['protection']['selected']})
            if protection_mounts[key]['selected']['mode'] == 'whole-root':
                # This host reads the unsealed on-disk root; it never mounts a sealed one.
                raise ContextError('Whole-root source protection cannot be mounted')
            from brain_protection import assess
            if not assess(declared.receipt()['requirements'], protection_mounts[key]['selected'])['supported']:
                raise ContextError('Selected source protection is unavailable')
            if protection_mounts[key]['selected']['mode'] == 'served':
                # This host is the mediator: only search reads the source, in process,
                # and releases addresses; composition and exact resolution refuse.
                served[key] = protection_mounts.pop(key)
                if capability != 'search':
                    continue
                if access_log is None:
                    raise ContextError('Served sources require an access log')
                protection = None
            elif capability != 'compose':
                continue
        records_config = settings["records"]
        if not isinstance(records_config, dict):
            raise ContextError("Invalid source records configuration")
        composition = records_config.get("kind") in ("brain-graph", "sqlite-graph", "code-graph")
        references = {}
        if records_config.get("kind") in ("brain-graph", "sqlite-graph"):
            references = read_pinned(base, records_config["references"])
        if records_config.get("kind") in ("sqlite-authority", "sqlite-graph"):
            fields(records_config, ("kind", "path", "bindingSha256", "references") if composition else
                   ("kind", "path", "bindingSha256"))
            if settings["realm"] != "brain" or descriptor["store"] != "structured":
                raise ContextError("SQLite records require a declared structured brain authority")
            text(records_config["path"])
            text(records_config["bindingSha256"])
            path = source_root(base, records_config["path"])
            if any(Path(str(path) + suffix).is_symlink() for suffix in ("-wal", "-shm", "-journal")):
                raise ContextError("Structured authority sidecars cannot follow symlinks")
            sources[settings["handle"]] = SQLiteRecordSource(
                path=path, expected_binding=records_config["bindingSha256"],
                participant=settings["participant"], authority=settings["authority"], boundary=source_boundary,
                consumer=boundary.actor, publications=read_pinned(base, settings["publications"]),
                composition=composition, references=references if composition else None, protection=protection)
            continue
        if records_config.get("kind") in ("brain", "brain-graph"):
            fields(records_config, ("kind", "graph", "references") if composition else ("kind", "graph"))
            graph = read_pinned(base, records_config["graph"])
            Registry(ontology).validate_graph(graph, require_binding=True)
            records = graph["nodes"]
            if settings["realm"] != "brain" or descriptor["store"] not in ("files", "journal", "structured"):
                raise ContextError("Brain records require a declared brain authority")
        elif records_config.get("kind") in ("code", "code-graph"):
            fields(records_config, ("kind", "descriptors"))
            if settings["realm"] != "code" or descriptor["store"] != "code":
                raise ContextError("Code records require a declared code authority")
            records = load_code_records(base, read_pinned(base, records_config["descriptors"]))
        else:
            raise ContextError("Unsupported local realm record loader")
        from federation_composition import LocalGraphSource
        source_class = LocalGraphSource if composition else LocalRecordSource
        graph_options = {"edges": graph["edges"] if settings["realm"] == "brain" else [],
                         "references": references} if composition else {}
        source = source_class(**graph_options, participant=settings["participant"], realm=settings["realm"],
                                    authority=settings["authority"], records=records, boundary=source_boundary,
                                    consumer=boundary.actor, publications=read_pinned(base, settings["publications"]),
                                    protection=protection)
        # A disagreement is kept as an explicit revision-changed resolution
        # outcome. A changed pinned input, by contrast, already failed loading.
        sources[settings["handle"]] = source
    remote = config.get("remoteSources", [])
    if not isinstance(remote, list):
        raise ContextError("Invalid remote source registrations")
    for settings in remote:
        fields(settings, ("handle", "participant", "realm", "authority", "endpoint", "credentials",
                          "ontology", "ca", "timeoutSeconds", "maxResponseBytes") +
               (('protection',) if 'protection' in settings else ()) +
               (('maxRequestBytes',) if 'maxRequestBytes' in settings else ()))
        for key in ("handle", "participant", "realm", "authority", "endpoint"):
            text(settings[key])
        if not isinstance(settings["credentials"], dict):
            raise ContextError("Remote credentials require an explicit consumer mapping")
        for consumer in settings["credentials"]:
            text(consumer)
        key = (settings["participant"], settings["realm"])
        if settings["handle"] in handles or key in realms:
            raise ContextError("Duplicate federation source handle or realm")
        handles.add(settings["handle"])
        realms.add(key)
        if selection is not None and key not in selection:
            continue
        descriptor = view.realm(*key)
        if descriptor is None or descriptor["transport"] != "remote":
            continue
        if selection is not None and descriptor['revision'] != selection[key]:
            continue
        if descriptor["handle"] != settings["handle"] or descriptor["authority"] != settings["authority"]:
            raise ContextError("Configured remote source disagrees with federation discovery")
        if descriptor["resolverVersion"] != "1.0" or descriptor["addressContract"] != "1.0" or "resolve" not in descriptor["capabilities"] or capability not in descriptor["capabilities"]:
            continue
        credential = consumer_mapping(settings["credentials"], boundary.actor, principals)
        if ((settings["realm"] == "code" and descriptor["store"] != "code")
                or (settings["realm"] == "brain" and descriptor["store"] not in ("files", "journal", "structured"))):
            raise ContextError("Remote realm disagrees with its authority class")
        if credential is None:
            raise ContextError("No remote credential mapping for this consumer")
        if 'protection' in settings:
            from federation_protection import mount
            protection_mounts[key] = mount(settings['protection'])
            if protection_mounts[key]['selected']['mode'] == 'served':
                raise ContextError('Served mode requires a local source mediated by this host')
            if capability != 'compose':
                continue
        raw_token = read_pinned(root, credential, raw=True)
        if len(raw_token) > 4096:
            raise ContextError("Remote credential exceeds its size limit")
        token = raw_token.decode("ascii").rstrip("\r\n")
        ca = read_pinned(root, settings["ca"], raw=True).decode("ascii") if settings["ca"] is not None else None
        ontology = read_pinned(root, settings["ontology"]) if settings["ontology"] is not None else None
        sources[settings["handle"]] = RemoteRecordSource(
            participant=settings["participant"], realm=settings["realm"], authority=settings["authority"],
            endpoint=settings["endpoint"], token=token, consumer=boundary.actor, ontology=ontology, ca_pem=ca,
            timeout=settings["timeoutSeconds"], max_response_bytes=settings["maxResponseBytes"],
            max_request_bytes=settings.get('maxRequestBytes', 65536))
    return FederationResolver(view, sources=sources, protection=protection_mounts, served=served,
                              access_log=access_log)


def load_references(root, config, *, boundary):
    return ReferencePlan(load_resolver(root, config, boundary=boundary), routes=read_pinned(root, config['routes']))


def load_search_host(root, config_path, *, actor, now, request, access_log=None):
    """Fresh operator-pinned discovery and sources, without a compulsory local graph."""
    from context_host import _read
    from federation_search import validate_request
    selected = validate_request(request)[:request['budget']['maxSources']]
    selection = {(s['participant'], s['realm']): s['revision'] for s in selected}
    root = Path(root)
    if root.is_symlink():
        raise ContextError('Federation search root cannot be a symlink')
    config = _read(root, config_path)
    fields(config, ('protocolVersion', 'policy', 'bindings', 'scopes', 'federation'))
    if config['protocolVersion'] != '1.0':
        raise ContextError('Unsupported federation search host configuration')
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    return load_resolver(root, read_pinned(root, config['federation']), boundary=boundary,
                         selection=selection, capability='search', access_log=access_log)


def load_basis_host(root, config_path, *, actor, now):
    """The fresh discovery view a serve-time consumer selects sources from (#209)."""
    from context_host import _read
    root = Path(root)
    if root.is_symlink():
        raise ContextError('Federation host root cannot be a symlink')
    config = _read(root, config_path)
    fields(config, ('protocolVersion', 'policy', 'bindings', 'scopes', 'federation'))
    if config['protocolVersion'] != '1.0':
        raise ContextError('Unsupported federation host configuration')
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    federation = read_pinned(root, config['federation'])
    return load_view(root, {key: federation[key] for key in DISCOVERY_FIELDS}, boundary=boundary)


def load_composition_host(root, config_path, *, actor, now, request):
    """Fresh selected graph sources using explicit graph loaders and capability."""
    from context_host import _read
    from federation_composition import validate_request
    selected = validate_request(request)[:request['budget']['maxSources']]
    selection = {(s['participant'], s['realm']): s['revision'] for s in selected}
    root = Path(root)
    if root.is_symlink():
        raise ContextError('Federation composition root cannot be a symlink')
    config = _read(root, config_path)
    fields(config, ('protocolVersion', 'policy', 'bindings', 'scopes', 'federation'))
    if config['protocolVersion'] != '1.0':
        raise ContextError('Unsupported federation composition host configuration')
    boundary, _ = load_boundary(root, config, actor=actor, now=now)
    return load_resolver(root, read_pinned(root, config['federation']), boundary=boundary,
                         selection=selection, capability='compose')
