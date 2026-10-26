"""Protected operations-host selection of an existing native writer.

The connection registration is host configuration, never an operation argument.
Credentials are resolved through the brain's existing environment DSN contract.
"""
import os
import re

from brain_federation import fields
from knowledge_store import StoreError, SQLiteAuthority, authority_class, resolve_store_dsn


def validate_connection(value):
    fields(value, ('store', 'driver', 'dsn'))
    fields(value['dsn'], ('env',))
    if (not isinstance(value['store'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', value['store'])
            or value['driver'] not in ('postgres', 'mysql')
            or not isinstance(value['dsn']['env'], str)
            or not re.fullmatch(r'[A-Z_][A-Z0-9_]{0,127}', value['dsn']['env'])):
        raise StoreError('Invalid registered native connection')


def supports(driver, operation):
    if driver == 'sqlite':
        return True
    return operation not in ('record.history', 'proposal.list', 'collection.browse') and not operation.startswith('intake.')


def select_backend(root, selected):
    from knowledge_operations import private_path

    if 'connection' not in selected:
        path = private_path(root, selected['path'])
        identity = (path.stat().st_dev, path.stat().st_ino)

        def current():
            info = private_path(root, selected['path']).stat()
            if (info.st_dev, info.st_ino) != identity:
                raise StoreError('Authority file changed during operation')

        return SQLiteAuthority, path, 'sqlite', None, current

    connection = selected['connection']
    validate_connection(connection)
    settings = {'brain': {'stores': [{'id': connection['store'], 'dsn': connection['dsn']}]}}
    target = resolve_store_dsn(settings, connection['store'])
    if not isinstance(target, str) or len(target) > 4096 or '\x00' in target:
        raise StoreError('Invalid registered connection value')
    adapter = authority_class(target)
    if getattr(getattr(adapter, 'dialect_class', None), 'driver', None) != connection['driver']:
        raise StoreError('Registered native connection driver differs from its DSN')

    def current():
        if os.environ.get(connection['dsn']['env']) != target:
            raise StoreError('Registered native connection changed during operation')

    return adapter, target, connection['driver'], connection['store'], current
