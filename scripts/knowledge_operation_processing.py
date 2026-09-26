"""Host-owned processing receipt selection for the existing native intake writer."""
from copy import deepcopy
import re

from brain_federation import fields
from context_access import ReadBoundary
from context_host import read_pinned
from federation_protection import SourceProtection
from intake_processed import MAX_BYTES, check, dependencies
from intake_recording import require_spool
from knowledge_policy import fingerprint, local_path
from knowledge_store import StoreError


def pin(value):
    fields(value, ('path', 'sha256'))
    if (local_path(value['path']).parts[0] != '_internal' or not isinstance(value['sha256'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])):
        raise StoreError('Private pinned processing state required')


def validate_registration(value):
    fields(value, ('protection', 'receipts'))
    pin(value['protection'])
    if not isinstance(value['receipts'], dict) or not 1 <= len(value['receipts']) <= 64:
        raise StoreError('Bounded processing receipt registrations required')
    seen = set()
    for identity, entry in value['receipts'].items():
        if not isinstance(identity, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', identity):
            raise StoreError('Invalid processing registration identity')
        fields(entry, ('receipt', 'receiptSha256', 'bindings', 'scopes', 'dependencies'))
        pin(entry['receipt'])
        pin(entry['bindings'])
        digest = entry['receiptSha256']
        if not isinstance(digest, str) or not re.fullmatch(r'[a-f0-9]{64}', digest) or digest in seen:
            raise StoreError('Unique processing receipt digest required')
        seen.add(digest)
        scopes = entry['scopes']
        if (not isinstance(scopes, list) or not 1 <= len(scopes) <= 64
                or any(not isinstance(scope, str) or not 1 <= len(scope) <= 2000 for scope in scopes)
                or len(set(scopes)) != len(scopes)):
            raise StoreError('Explicit processing scopes required')
        rows = entry['dependencies']
        if not isinstance(rows, list) or not 1 <= len(rows) <= 8:
            raise StoreError('Explicit processing dependency headers required')
        for row in rows:
            if (not isinstance(row, list) or len(row) != 3
                    or any(not isinstance(text, str) or not 1 <= len(text) <= 2000 for text in row)
                    or not re.fullmatch(r'[a-f0-9]{64}', row[0])):
                raise StoreError('Invalid processing dependency header')
        if len({tuple(row) for row in rows}) != len(rows):
            raise StoreError('Duplicate processing dependency header')


class ProcessingOperations:
    def __init__(self, intake, registration):
        validate_registration(registration)
        self.intake, self.registration = intake, deepcopy(registration)
        self.pending = set()
        intake.store.intake_processing_protection = self.protection
        intake.store.intake_processing_reuse = self.reuse

    def read(self, descriptor, *, limit):
        from knowledge_operations import private_path

        self.intake.guard()
        private_path(self.intake.root, descriptor['path'])
        return read_pinned(self.intake.root, descriptor, max_bytes=limit)

    def protection(self):
        return SourceProtection(self.read(self.registration['protection'], limit=1048576),
                                resources=self.intake.store.contract.policy.resources)

    def load(self, identity, *, actor, at):
        entry = self.registration['receipts'].get(identity)
        if entry is None:
            raise StoreError('Processing receipt is not registered')
        boundary = ReadBoundary(self.intake.store.contract.policy, actor=actor, now=at,
            scopes=entry['scopes'], bindings=self.read(entry['bindings'], limit=1048576))
        # Authorize host-owned headers before opening the retained content.
        for reference, resource, subject in entry['dependencies']:
            if (boundary.bindings['references'].get(reference) != resource
                    or not boundary.permits('references', reference)
                    or not boundary.permits_resource(resource, subject)):
                raise StoreError('Processing dependency unavailable')
        require_spool(self.protection().for_resources([row[1] for row in entry['dependencies']]))
        receipt = self.read(entry['receipt'], limit=MAX_BYTES)
        if (not isinstance(receipt, dict) or not isinstance(receipt.get('item'), dict)
                or fingerprint(receipt) != entry['receiptSha256']
                or fingerprint(boundary.bindings) != receipt.get('bindingsSha256')
                or sorted(boundary.scopes) != receipt.get('scopes')):
            raise StoreError('Processing receipt or boundary changed')
        resource = boundary.bindings['references'].get(fingerprint(receipt['item']))
        if resource not in boundary.policy.resources:
            raise StoreError('Processing source binding unavailable')
        representation = {'sha256': entry['receiptSha256'], 'receipt': receipt,
                          'sourceResource': resource, 'scope': boundary.policy.resources[resource]['scope']}
        check(representation, 'representation')
        if sorted(map(tuple, entry['dependencies'])) != sorted(dependencies(representation)):
            raise StoreError('Processing dependency headers differ from retained evidence')
        self.pending.add((identity, actor))
        return receipt, boundary

    def identity(self, digest):
        for identity, entry in self.registration['receipts'].items():
            if entry['receiptSha256'] == digest:
                return identity
        raise StoreError('Processing receipt registration was withdrawn')

    def validate_proposal(self, representation, *, actor, at):
        receipt, _ = self.load(self.identity(representation['sha256']), actor=actor, at=at)
        if receipt != representation['receipt']:
            raise StoreError('Registered processing differs from the proposed receipt')

    def reuse(self, receipt, *, actor, at):
        self.load(self.identity(fingerprint(receipt)), actor=actor, at=at)
        planner = self.intake.planner(actor, at, self.intake.no_inference)
        provider = getattr(planner, 'processing_reuse_authorization', None)
        if not callable(provider):
            raise StoreError('Current processing reuse host selection required')
        return provider(receipt, actor=actor, at=at)

    def revalidate(self, at):
        for identity, actor in tuple(self.pending):
            self.load(identity, actor=actor, at=at)
