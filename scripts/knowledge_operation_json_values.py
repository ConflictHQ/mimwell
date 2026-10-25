"""Explicit v11 JSON value strings, same selected grants and canonical writer."""
import re

from knowledge_file_json_values import decode_field_wires
from knowledge_operation_file_records import run_record_authority
from knowledge_store import StoreError

COORDINATES = {'recordIndex', 'expectedRevision', 'expectedSelectionSha256', 'expectedRecordSha256', 'fieldWires'}


def validate_value_arguments(operation, args):
    if not isinstance(args, dict):
        raise StoreError('Invalid JSON value arguments')
    if operation == 'authority.inspect' and args == {}:
        return
    preview = operation == 'file.inspect' and set(args) == COORDINATES
    required = ({'recordIndex'} if operation == 'file.inspect' and not preview else
                COORDINATES | {'requestId', 'reason'} if operation == 'file.propose' else
                COORDINATES if preview else None)
    if required is None or set(args) != required or type(args['recordIndex']) is not int or not 0 <= args['recordIndex'] <= 65535:
        raise StoreError('Unsupported explicit JSON value operation')
    if operation == 'file.inspect' and not preview:
        return
    for key in ('expectedRevision', 'expectedSelectionSha256', 'expectedRecordSha256'):
        if not isinstance(args[key], str) or re.fullmatch(r'[a-f0-9]{64}', args[key]) is None:
            raise StoreError('Exact JSON value source basis required')
    decode_field_wires(args['fieldWires'])
    if operation == 'file.propose' and (not isinstance(args['requestId'], str) or
            re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}', args['requestId']) is None or
            not isinstance(args['reason'], str) or not args['reason'].strip() or len(args['reason']) > 2000):
        raise StoreError('Original JSON value request identity and reason required')


def run_value_authority(root, host_config, host, selected, request, **context):
    # One existing host/identity/final-currentness implementation. The optional
    # mode is trusted server selection, never a caller-selected writer or DSN.
    return run_record_authority(root, host_config, host, selected, request,
                                _value_mode=True, **context)
