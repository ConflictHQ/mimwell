"""Operator-owned WSGI factory for the optional isolated context-service reference."""
import os
from pathlib import Path
import stat

from context_host import read_json
from context_http import ContextApplication, ContextEndpoint
from knowledge_store import authority_class


def private(path):
    """A regular file in a directory, both owned by this user and closed to everyone else."""
    path = Path(path)
    for selected in (path.parent, path):
        info = selected.lstat()
        required = stat.S_ISDIR if selected == path.parent else stat.S_ISREG
        if not required(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError('Credentials require private operator-owned paths')
    return path


def credentials(path):
    """Read the current credential file after each atomic directory-mounted rotation."""
    return read_json(private(path))


def authority(root, dsn):
    """BRAIN_CANON_DSN selects live mode: a postgres/mysql URL, or a SQLite path absolute or under the root."""
    if not dsn:
        return None
    authority_class(dsn)  # Refuse a scheme with no authority driver at startup.
    if '://' in dsn:
        return dsn
    path = Path(root) / dsn
    if not path.is_file():
        raise ValueError('BRAIN_CANON_DSN does not name an authority file')
    return path


def canon_dsn():
    """BRAIN_CANON_DSN, or BRAIN_CANON_DSN_FILE: a private file holding a DSN whose password stays out of the environment."""
    dsn, path = os.environ.get('BRAIN_CANON_DSN'), os.environ.get('BRAIN_CANON_DSN_FILE')
    if not path:
        return dsn
    if dsn:
        raise ValueError('Set BRAIN_CANON_DSN or BRAIN_CANON_DSN_FILE, not both')
    return private(path).read_text().strip()


def usage_log(path):
    """Append one JSON line per successfully answered request to an operator-owned file (#348).

    Required only alongside the brain's own host-config ``usageLog`` opt-in
    (scripts/context_host.py); either absent means nothing is written.
    """
    def append(entry):
        from context_bundle import encode
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.write(descriptor, encode(entry))
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    return append


def create_application():
    """One explicit root/host per process; no request-controlled deployment settings."""
    root = os.environ['BRAIN_ROOT']
    host = os.environ.get('BRAIN_CONTEXT_HOST', '_internal/context-host.json')
    path = Path(os.environ['BRAIN_CONTEXT_CREDENTIALS'])
    credentials(path)  # Refuse unsafe/unreadable credential placement at startup.
    app_host = os.environ.get('BRAIN_APPS_HOST')
    if app_host:
        from app_backend_http import AppApplication
        selected = authority(root, canon_dsn())
        if selected is None:
            raise ValueError('App backend requires a live authority')
        bundle_root = os.environ.get('BRAIN_APP_BUNDLE_ROOT')
        browser_proxy_prefix = os.environ.get('BRAIN_APP_BROWSER_PROXY_PREFIX')
        if browser_proxy_prefix and not bundle_root:
            raise ValueError('Browser-proxy app presentation requires BRAIN_APP_BUNDLE_ROOT')
        operations_root = None
        if bundle_root:
            configured_operations_root = os.environ.get('BRAIN_OPERATIONS_ROOT')
            if not configured_operations_root:
                raise ValueError('Private app bundles require BRAIN_OPERATIONS_ROOT')
            operations_root = Path(configured_operations_root).absolute()
        publication_registry = os.environ.get('BRAIN_APP_PUBLICATION_REGISTRY')
        host_brain_id = os.environ.get('BRAIN_APP_HOST_BRAIN_ID')
        host_environment_id = os.environ.get('BRAIN_APP_ENVIRONMENT_ID')
        return AppApplication(root=root, host_config=app_host, authority=selected,
                              credentials=lambda: credentials(path),
                              operations_root=operations_root,
                              bundle_root=bundle_root,
                              browser_proxy_prefix=browser_proxy_prefix,
                              publication_registry=publication_registry,
                              host_brain_id=host_brain_id,
                              host_environment_id=host_environment_id)
    log = os.environ.get('BRAIN_CONTEXT_USAGE_LOG')
    return ContextApplication(ContextEndpoint(root=root, host_config=host,
        credentials=lambda: credentials(path), max_concurrent=1,
        authority=authority(root, canon_dsn()), usage_log=usage_log(log) if log else None))
