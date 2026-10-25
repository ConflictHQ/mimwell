"""Explicit registered-JSON record mode; same host grants and canonical Git writer."""
import re

from knowledge_policy import fingerprint, timestamp
from knowledge_store import StoreError

ARGUMENTS = {
    "authority.inspect": (),
    "file.inspect": ("recordIndex",),
    "file.propose": ("expectedRevision", "expectedSelectionSha256", "recordIndex",
                     "expectedRecordSha256", "fields", "requestId", "reason"),
}


def validate_record_arguments(operation, args):
    if operation not in ARGUMENTS or not isinstance(args, dict) or set(args) != set(ARGUMENTS[operation]):
        raise StoreError("Unsupported registered JSON record operation")
    if operation == "authority.inspect":
        return
    if type(args["recordIndex"]) is not int or not 0 <= args["recordIndex"] <= 65535:
        raise StoreError("Invalid selected record coordinate")
    if operation == "file.inspect":
        return
    for key in ("expectedRevision", "expectedSelectionSha256", "expectedRecordSha256"):
        if not isinstance(args[key], str) or not re.fullmatch(r"[0-9a-f]{64}", args[key]):
            raise StoreError("Exact selected source and record basis required")
    if (not isinstance(args["requestId"], str) or
            not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", args["requestId"]) or
            not isinstance(args["reason"], str) or not args["reason"].strip() or len(args["reason"]) > 2000):
        raise StoreError("A request identity and bounded change reason are required")
    values = args["fields"]
    if not isinstance(values, dict) or not 1 <= len(values) <= 64:
        raise StoreError("A bounded record correction is required")
    total = 0
    try:
        for name, value in values.items():
            if not isinstance(name, str) or not 1 <= len(name) <= 2000:
                raise StoreError("Invalid correction field")
            total += len(name.encode("utf-8"))
            items = [value] if isinstance(value, str) else value
            if not isinstance(items, list) or len(items) > 256:
                raise StoreError("Correction fields require bounded text values")
            for item in items:
                if not isinstance(item, str) or len(item) > 65536:
                    raise StoreError("Correction fields require bounded text values")
                total += len(item.encode("utf-8"))
                if total > 131072:
                    raise StoreError("Record correction exceeds bound")
    except UnicodeError as exc:
        raise StoreError("Correction fields require UTF-8") from exc


def run_record_authority(root, host_config, host, selected, request, *, actor, clock, authorize, max_response_bytes, _value_mode=False):
    from git_file_authoring import _load_pins, capabilities, run_operation
    from knowledge_operations import _file_authority_response, load_host

    operation, args = request["operation"], request["arguments"]
    if _value_mode:
        from knowledge_operation_json_values import validate_value_arguments
        validate_value_arguments(operation, args)
    else:
        validate_record_arguments(operation, args)
    if selected["writer"] != "json-commit" or operation not in selected["grants"].get(actor, []):
        raise StoreError("Registered JSON record operation unavailable")
    initial = timestamp(clock())

    def guard(not_before=initial):
        if authorize is not None and authorize() != actor:
            raise StoreError("Operation identity changed")
        if load_host(root, host_config) != host or timestamp(clock()) < not_before:
            raise StoreError("Operation host selection changed")

    guard()
    pin = _load_pins(root, selected)
    binding = fingerprint(selected)
    if operation == "authority.inspect":
        native = {"authority": request["authority"], "driver": "files", "collections": [],
                  "hostCapabilities": {"format": "authoring-capabilities/v1", "authority": request["authority"],
                    "principal": actor, "binding": binding, "operations": capabilities(selected, actor),
                    "authorization": "host-registration-only", "nativePolicy": "required-per-operation",
                    "executionAuthorized": False, "fileRecordVersions": ["v11"] if _value_mode else ["v10"],
                    "fileWriter": {"path": pin["path"], "writer": selected["writer"], "schema": selected["schema"]}}}
    else:
        if _value_mode and operation == "file.inspect" and "fieldWires" in args and args["expectedSelectionSha256"] != binding:
            raise StoreError("File writer registration changed before preview")
        if operation == "file.propose" and args["expectedSelectionSha256"] != binding:
            raise StoreError("File writer registration changed; inspect again")
        native = run_operation(root, selected, operation, args, actor=actor,
                               actors=tuple(selected["grants"]), clock=clock, guard=guard,
                               record_mode="registered-json-record/v2" if _value_mode else "registered-json-record/v1")
        if operation == "file.inspect":
            if native["sourceCommit"] != pin["sourceCommit"]:
                raise StoreError("File source changed during record inspection")
            native["selectionSha256"] = binding
    final_at = clock()
    if timestamp(final_at) < initial:
        raise StoreError("Operation clock moved backwards")
    guard(not_before=timestamp(final_at))
    pin_now = _load_pins(root, selected)
    if pin_now["schemaBytes"] != pin["schemaBytes"] or pin_now["sourceCommit"] != pin["sourceCommit"]:
        raise StoreError("File writer source changed during record operation")
    return _file_authority_response(request, native, actor, initial.isoformat(), final_at,
                                   binding, max_response_bytes)
