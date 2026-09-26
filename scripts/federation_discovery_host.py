"""Pinned discovery metadata only; no record or transport loaders."""
from brain_federation import FederationCatalog, fields
from context_bundle import ContextError
from context_host import MAX_INPUT_BYTES, decode, read_pinned

DISCOVERY_FIELDS = ("protocolVersion", "catalog", "inventory", "manifests", "discoveryBindings", "reviewedSubjects")


def load_discovery(root, config, *, max_metadata_bytes=None, max_manifests=None):
    """Load only enrollment observations and discovery policy; never source records."""
    fields(config, DISCOVERY_FIELDS)
    if config["protocolVersion"] != "1.0" or not isinstance(config["manifests"], dict):
        raise ContextError("Invalid discovery host configuration")
    if max_manifests is not None and len(config["manifests"]) > max_manifests:
        raise ContextError("Discovery manifest budget exceeded")
    used = 0

    def read(descriptor, *, raw=False):
        nonlocal used
        remaining = MAX_INPUT_BYTES if max_metadata_bytes is None else min(MAX_INPUT_BYTES, max_metadata_bytes - used)
        content = read_pinned(root, descriptor, raw=True, max_bytes=remaining)
        used += len(content)
        if max_metadata_bytes is not None and used > max_metadata_bytes:
            raise ContextError("Discovery metadata budget exceeded")
        return content if raw else decode(content)

    document = read(config["catalog"])
    inventory = read(config["inventory"])
    manifests = {location: read(descriptor, raw=True) for location, descriptor in config["manifests"].items()}
    catalog = FederationCatalog(document, inventory=inventory, manifests=manifests)
    return catalog, read(config["discoveryBindings"]), read(config["reviewedSubjects"])


def load_view(root, config, *, boundary, max_metadata_bytes=None, max_manifests=None):
    catalog, bindings, reviews = load_discovery(root, config, max_metadata_bytes=max_metadata_bytes,
                                               max_manifests=max_manifests)
    return catalog.scoped(boundary, bindings=bindings, reviewed_subjects=reviews)
