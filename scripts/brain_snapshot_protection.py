"""Bounded ciphertext container for host-admitted snapshot capture.

This module does not select a provider or grant. The embedding host constructs
the adapter from its trusted ProtectionHost and the current adopted registration.
"""
import hashlib
import json
import math
import os
import re
import secrets
from pathlib import Path

from brain_protection import (MAX_PROTECTED_BYTES, MAX_PROTECTED_ENVELOPE,
                              ProtectionError, ProtectionHost, assess, profile,
                              requirements)
from knowledge_policy import fingerprint

FORMAT = "protected-snapshot/v1"
CHUNK_FORMAT = "protected-snapshot-chunk/v1"
CHUNK_BYTES = 8 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 64 * 1024 * 1024
MAX_CHUNKS = 8
MAX_ENTRIES = 10_000
MAX_MANIFEST_BYTES = 64 * 1024
ENVELOPE_OVERHEAD_BOUND = 256 * 1024


class SnapshotProtectionError(ValueError):
    """A protected snapshot failed its closed format or host policy checks."""


def _canonical(value):
    try:
        return (json.dumps(value, sort_keys=True, separators=(",", ":"),
                            ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise SnapshotProtectionError("protected-snapshot-json-invalid") from exc


def _sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def protected_peak_bound(plaintext_upper_bound):
    """Conservative retained-file bound, including envelope and index overhead."""
    if (type(plaintext_upper_bound) is not int or plaintext_upper_bound <= 0
            or plaintext_upper_bound > MAX_PLAINTEXT_BYTES):
        raise SnapshotProtectionError("protected-snapshot-size-bound")
    count = math.ceil(plaintext_upper_bound / CHUNK_BYTES)
    if count > MAX_CHUNKS:
        raise SnapshotProtectionError("protected-snapshot-chunk-bound")
    remaining = plaintext_upper_bound
    encoded_chunks = 0
    for _ in range(count):
        chunk_bytes = min(CHUNK_BYTES, remaining)
        encoded_chunks += 4 * math.ceil((chunk_bytes + 16) / 3) + ENVELOPE_OVERHEAD_BOUND
        remaining -= chunk_bytes
    # The outer manifest has fixed-width digests, bounded names and at most eight
    # rows. Leave room for its canonical encoding and final self-digest.
    return encoded_chunks + MAX_MANIFEST_BYTES


class SnapshotProtectionAdapter:
    """Immutable host-owned provider binding for one adopted brain registration."""

    def __init__(self, *, root, registration, provider, required, selected):
        if not isinstance(provider, ProtectionHost):
            raise SnapshotProtectionError("snapshot-protection-provider-unavailable")
        self.root = str(Path(root).resolve(strict=True))
        from brain_storage_admission import _open_directory_chain
        root_fd = _open_directory_chain(self.root)
        try:
            root_info = os.fstat(root_fd)
            self.root_identity = (root_info.st_dev, root_info.st_ino)
        finally:
            os.close(root_fd)
        self.registration_sha256 = fingerprint(registration)
        self.authority_binding = registration["authority"]["binding"]
        self.provider = provider
        self.actor = provider.actor
        if not isinstance(self.actor, str) or not self.actor:
            raise SnapshotProtectionError("snapshot-protection-provider-actor-changed")
        self.required = requirements(required)
        self.selected = profile(selected)
        if (self.selected["mode"] != "per-record"
                or registration["protection"]["profile"] != "per-record"
                or fingerprint(self.required) != registration["protection"]["requirementsSha256"]
                or self.required["opaqueMetadata"]
                or not assess(self.required, self.selected, offline=True,
                              operation="retain")["supported"]):
            raise SnapshotProtectionError("snapshot-protection-requirements-unavailable")
        self.profile_sha256 = fingerprint(self.selected)
        self.requirements_sha256 = fingerprint(self.required)
        self.provider_actor_sha256 = _sha256(self.actor.encode("utf-8"))
        try:
            self._assert_provider_actor()
            self.provider.available(self.selected)
            self._assert_provider_actor()
        except ProtectionError as exc:
            raise SnapshotProtectionError("snapshot-protection-provider-unavailable") from exc

    def _assert_provider_actor(self):
        actor = getattr(self.provider, "actor", None)
        if (not isinstance(actor, str) or actor != self.actor
                or _sha256(actor.encode("utf-8")) != self.provider_actor_sha256):
            raise SnapshotProtectionError("snapshot-protection-provider-actor-changed")

    def verify(self, *, root, registration):
        self._assert_provider_actor()
        from brain_storage_admission import _open_directory_chain
        root_fd = _open_directory_chain(root)
        try:
            root_info = os.fstat(root_fd)
            current_root_identity = (root_info.st_dev, root_info.st_ino)
        finally:
            os.close(root_fd)
        if (str(Path(root).resolve(strict=True)) != self.root
                or current_root_identity != self.root_identity
                or fingerprint(self.selected) != self.profile_sha256
                or fingerprint(self.required) != self.requirements_sha256
                or _sha256(self.actor.encode("utf-8")) != self.provider_actor_sha256
                or fingerprint(registration) != self.registration_sha256
                or registration["authority"]["binding"] != self.authority_binding
                or registration["protection"]["profile"] != "per-record"
                or registration["protection"]["requirementsSha256"] != self.requirements_sha256):
            raise SnapshotProtectionError("snapshot-protection-binding-changed")
        try:
            self.provider.available(self.selected)
            self._assert_provider_actor()
        except ProtectionError as exc:
            raise SnapshotProtectionError("snapshot-protection-provider-unavailable") from exc

    def reauthorize(self, envelope):
        self._assert_provider_actor()
        header = {key: envelope[key] for key in (
            "format", "object", "revision", "requirements", "profile",
            "contextSha256", "contentBytes", "contentSha256")}
        try:
            self.provider.permit(header, "retain")
            self._assert_provider_actor()
        except ProtectionError as exc:
            raise SnapshotProtectionError("snapshot-protection-policy-changed") from exc

    def context(self, *, snapshot_id, chunk_index, chunk_count):
        return {"format": CHUNK_FORMAT, "snapshotId": snapshot_id,
                "registrationSha256": self.registration_sha256,
                "providerActorSha256": self.provider_actor_sha256,
                "authorityBinding": self.authority_binding,
                "profileSha256": self.profile_sha256,
                "requirementsSha256": self.requirements_sha256,
                "chunkIndex": chunk_index, "chunkCount": chunk_count}

    def seal(self, raw, *, context):
        self._assert_provider_actor()
        object_id, revision = secrets.token_hex(16), secrets.token_hex(16)
        try:
            envelope = self.provider.seal_bytes(raw, context=context, object_id=object_id,
                revision=revision, required=self.required, selected=self.selected)
            self._assert_provider_actor()
            return envelope
        except ProtectionError as exc:
            raise SnapshotProtectionError("snapshot-protection-seal-unavailable") from exc

    def open(self, envelope, *, context):
        self._assert_provider_actor()
        try:
            raw = self.provider.open_bytes(envelope, context=context,
                expected_object=envelope["object"], expected_revision=envelope["revision"],
                expected_profile=self.selected, required=self.required)
            self._assert_provider_actor()
            return raw
        except (ProtectionError, KeyError, TypeError) as exc:
            raise SnapshotProtectionError("snapshot-protection-open-unavailable") from exc


def seal_payload(payload, *, adapter, plan_sha256, source_basis_sha256):
    """Seal one bounded archive into independently authenticated fixed-size chunks."""
    if (not isinstance(payload, bytes) or not payload
            or len(payload) > MAX_PLAINTEXT_BYTES
            or not re.fullmatch(r"[0-9a-f]{64}", plan_sha256 or "")
            or not re.fullmatch(r"[0-9a-f]{64}", source_basis_sha256 or "")):
        raise SnapshotProtectionError("protected-snapshot-payload-invalid")
    chunk_count = math.ceil(len(payload) / CHUNK_BYTES)
    if not 1 <= chunk_count <= MAX_CHUNKS:
        raise SnapshotProtectionError("protected-snapshot-chunk-bound")
    snapshot_id = secrets.token_hex(16)
    context_base = {"format": FORMAT, "snapshotId": snapshot_id,
                    "registrationSha256": adapter.registration_sha256,
                    "providerActorSha256": adapter.provider_actor_sha256,
                    "authorityBinding": adapter.authority_binding,
                    "profileSha256": adapter.profile_sha256,
                    "requirementsSha256": adapter.requirements_sha256,
                    "chunkCount": chunk_count}
    chunks = []
    for index in range(chunk_count):
        raw = payload[index * CHUNK_BYTES:(index + 1) * CHUNK_BYTES]
        if len(raw) > MAX_PROTECTED_BYTES:
            raise SnapshotProtectionError("protected-snapshot-chunk-bound")
        context = adapter.context(snapshot_id=snapshot_id, chunk_index=index,
                                  chunk_count=chunk_count)
        context["chunkSha256"] = _sha256(raw)
        context["chunkBytes"] = len(raw)
        envelope = adapter.seal(raw, context=context)
        encoded = _canonical(envelope)
        if len(encoded) > MAX_PROTECTED_ENVELOPE + ENVELOPE_OVERHEAD_BOUND:
            raise SnapshotProtectionError("protected-snapshot-envelope-bound")
        chunks.append({"name": f"{index:06d}.json", "bytes": encoded, "envelope": envelope,
                       "sha256": _sha256(encoded), "size": len(encoded)})
    manifest = {**context_base,
        "chunks": [{"name": row["name"], "bytes": row["size"],
                    "sha256": row["sha256"]} for row in chunks]}
    manifest["sha256"] = fingerprint(manifest)
    encoded_manifest = _canonical(manifest)
    if len(encoded_manifest) > MAX_MANIFEST_BYTES:
        raise SnapshotProtectionError("protected-snapshot-manifest-bound")
    actual_total = len(encoded_manifest) + sum(row["size"] for row in chunks)
    peak_bound = protected_peak_bound(len(payload))
    if actual_total > peak_bound:
        raise SnapshotProtectionError("protected-snapshot-ciphertext-bound")
    return {"manifest": manifest, "manifestBytes": encoded_manifest, "chunks": chunks,
            "peakBoundBytes": peak_bound}


def decode_manifest(raw):
    """Decode the bounded canonical outer manifest before traversing its fields."""
    if not isinstance(raw, bytes) or len(raw) > MAX_MANIFEST_BYTES:
        raise SnapshotProtectionError("protected-snapshot-manifest-bound")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
        raise SnapshotProtectionError("protected-snapshot-manifest-invalid") from exc
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise SnapshotProtectionError("protected-snapshot-manifest-noncanonical")
    return value


def open_payload(manifest_bytes, chunk_envelopes, *, adapter):
    """Authenticate an in-memory container; filesystem opening stays with its host."""
    manifest = decode_manifest(manifest_bytes)
    if (not isinstance(manifest, dict) or set(manifest) != {
            "format", "snapshotId", "registrationSha256", "providerActorSha256", "authorityBinding",
            "profileSha256", "requirementsSha256", "chunkCount", "chunks", "sha256"}
            or manifest.get("format") != FORMAT or not isinstance(manifest.get("chunks"), list)
            or type(manifest.get("chunkCount")) is not int
            or not re.fullmatch(r"[0-9a-f]{32}", manifest.get("snapshotId", ""))
            or not all(re.fullmatch(r"[0-9a-f]{64}", manifest.get(key, ""))
                       for key in ("registrationSha256", "providerActorSha256", "profileSha256",
                                   "requirementsSha256", "sha256"))
            or not isinstance(manifest.get("authorityBinding"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("authorityBinding", ""))
            or len(manifest["chunks"]) != manifest.get("chunkCount")
            or not 1 <= len(manifest["chunks"]) <= MAX_CHUNKS
            or not isinstance(chunk_envelopes, (list, tuple))
            or len(chunk_envelopes) != len(manifest["chunks"])):
        raise SnapshotProtectionError("protected-snapshot-manifest-invalid")
    unsigned = {key: value for key, value in manifest.items() if key != "sha256"}
    if fingerprint(unsigned) != manifest["sha256"]:
        raise SnapshotProtectionError("protected-snapshot-manifest-digest")
    expected = {"registrationSha256": adapter.registration_sha256,
                "providerActorSha256": adapter.provider_actor_sha256,
                "authorityBinding": adapter.authority_binding,
                "profileSha256": adapter.profile_sha256,
                "requirementsSha256": adapter.requirements_sha256}
    if any(manifest.get(key) != value for key, value in expected.items()):
        raise SnapshotProtectionError("protected-snapshot-context-changed")
    output = bytearray()
    encoded_total = len(manifest_bytes)
    for index, (row, encoded) in enumerate(zip(manifest["chunks"], chunk_envelopes)):
        if (not isinstance(row, dict) or set(row) != {"name", "bytes", "sha256"}
                or row["name"] != f"{index:06d}.json" or type(row["bytes"]) is not int
                or row["bytes"] <= 0 or row["bytes"] > MAX_PROTECTED_ENVELOPE + ENVELOPE_OVERHEAD_BOUND
                or not isinstance(row["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", row["sha256"])
                or not isinstance(encoded, bytes) or len(encoded) != row["bytes"]
                or _sha256(encoded) != row["sha256"]):
            raise SnapshotProtectionError("protected-snapshot-chunk-list-invalid")
        encoded_total += len(encoded)
        if encoded_total > protected_peak_bound(MAX_PLAINTEXT_BYTES):
            raise SnapshotProtectionError("protected-snapshot-ciphertext-bound")
        try:
            envelope = json.loads(encoded, object_pairs_hook=_unique_object,
                                  parse_constant=_reject_constant)
        except (ValueError, UnicodeDecodeError, TypeError, RecursionError) as exc:
            raise SnapshotProtectionError("protected-snapshot-envelope-invalid") from exc
        if _canonical(envelope) != encoded:
            raise SnapshotProtectionError("protected-snapshot-envelope-noncanonical")
        if (len(encoded) > MAX_PROTECTED_ENVELOPE + ENVELOPE_OVERHEAD_BOUND
                or not isinstance(envelope, dict)):
            raise SnapshotProtectionError("protected-snapshot-envelope-bound")
        context = adapter.context(snapshot_id=manifest["snapshotId"],
            chunk_index=index, chunk_count=manifest["chunkCount"])
        context["chunkSha256"] = envelope.get("contentSha256")
        context["chunkBytes"] = envelope.get("contentBytes")
        raw = adapter.open(envelope, context=context)
        if (len(raw) > CHUNK_BYTES or not raw
                or (index < len(manifest["chunks"]) - 1 and len(raw) != CHUNK_BYTES)
                or envelope.get("contextSha256") != fingerprint({**context,
                    "chunkSha256": _sha256(raw), "chunkBytes": len(raw)})):
            raise SnapshotProtectionError("protected-snapshot-chunk-context")
        output.extend(raw)
        if len(output) > MAX_PLAINTEXT_BYTES:
            raise SnapshotProtectionError("protected-snapshot-plaintext-bound")
    return bytes(output)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotProtectionError("protected-snapshot-json-duplicate-key")
        result[key] = value
    return result


def _reject_constant(_value):
    raise SnapshotProtectionError("protected-snapshot-json-nonfinite")
