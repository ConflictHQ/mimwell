"""Bounded observations of registered local sources, without capture persistence.

The embedding host owns the registration, root, budget and fresh boundary factory.
This is not a caller-supplied-path endpoint. An observation is a captured fact, not
a continuing access grant; the service must fence its host selection before release.
"""

from copy import deepcopy
import hashlib

from intake_capture import CaptureError, authorize, read_stable
from knowledge_policy import fingerprint, timestamp

MAX_SOURCE_BYTES = 16 * 1024 * 1024


def observe_source(current_boundary, registration, *, root, max_bytes):
    """Read one authorized item; refuse auth changes even when the probe fails."""
    if not callable(current_boundary) or type(max_bytes) is not int or not 1 <= max_bytes <= MAX_SOURCE_BYTES:
        raise CaptureError("Invalid source observation host")
    registration = deepcopy(registration)
    initial = current_boundary()
    authorize(initial, registration)  # Authorization precedes filesystem access.
    initial_actor, initial_now = initial.actor, initial.now
    observed = {
        "format": "source-health/v1",
        "source": registration["id"],
        "registrationSha256": fingerprint(registration),
        "scope": "one-registered-local-source",
        "probe": "bounded-stable-regular-file-read",
        "observedAt": initial_now,
        "availability": "unavailable",
        "reason": "source-unavailable-within-probe-bound",
        "sourceSha256": None,
        "sourceBytes": None,
        "filesystemObservationSha256": None,
        "expectedSourceSha256": registration["sha256"],
        "revisionState": "unknown",
        "upstreamFreshness": "unknown",
        "maxSourceBytes": max_bytes,
        "executionAuthorized": False,
    }
    try:
        raw, filesystem = read_stable(root, registration["path"], max_bytes)
    except (OSError, CaptureError):
        # A missing, changed, oversized or unsafe source is an observation for an
        # authorized operator. Do not disclose paths, exception text or partial bytes.
        pass
    else:
        digest = hashlib.sha256(raw).hexdigest()
        expected = registration["sha256"]
        observed.update(
            availability="available", reason="bounded-source-read-completed",
            sourceSha256=digest, sourceBytes=len(raw),
            filesystemObservationSha256=fingerprint(filesystem),
            revisionState="unasserted" if expected is None else "matched" if digest == expected else "mismatched",
        )
    final = current_boundary()
    if final is initial:
        raise CaptureError("Source observation requires fresh authorization boundaries")
    authorize(final, registration)
    if final.actor != initial_actor or timestamp(final.now) < timestamp(initial_now):
        raise CaptureError("Source observation authorization changed")
    observed["authorization"] = {
        "principal": final.actor, "evaluatedAt": final.now,
        "scopes": sorted(final.scopes), "policy": deepcopy(final.policy.binding),
    }
    observed["basisSha256"] = fingerprint(observed)
    return observed
