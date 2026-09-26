"""Shared intake history and local delivery adapters over the native writer."""
from copy import deepcopy
from functools import partial
import re

from brain_federation import fields
from context_host import read_pinned
from intake import IntakeAuthority
from intake_contract import check, validate_history
from intake_delivery import check as check_delivery
from intake_host import load_planner
from knowledge_policy import fingerprint, local_path, timestamp
from knowledge_store import StoreError
from maintenance_audit import audit, operation as log_operation


def text(value, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise StoreError("Invalid bounded intake operation text")


def validate_registration(value):
    if not isinstance(value, dict):
        raise StoreError("Intake host registration must be an object")
    fields(value, ("planner", "collection", "destinations") + tuple(k for k in ("processing", "completion") if k in value))
    if "completion" in value:
        fields(value['completion'], ('index',))
        if local_path(value['completion']['index']).parts[0] != '_internal':
            raise StoreError('Completion index must be privately registered')
    if "processing" in value:
        from knowledge_operation_processing import validate_registration as validate_processing

        validate_processing(value['processing'])
    fields(value["planner"], ("path", "sha256"))
    if local_path(value["planner"]["path"]).parts[0] != "_internal":
        raise StoreError("Intake planner must be privately registered")
    if not isinstance(value["planner"]["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["planner"]["sha256"]):
        raise StoreError("Pinned intake planner required")
    text(value["collection"])
    if not isinstance(value["destinations"], dict) or not 1 <= len(value["destinations"]) <= 64:
        raise StoreError("Bounded intake destinations required")
    for identity, target in value["destinations"].items():
        text(identity)
        check_delivery(target, "registration")


def validate_arguments(operation, args):
    if operation == 'intake.completion-refresh':
        if (type(args['maxEvents']) is not int or not 1 <= args['maxEvents'] <= 1000
                or type(args['maxBytes']) is not int or not 1 <= args['maxBytes'] <= 16777216):
            raise StoreError('Invalid completion refresh budget')
    for key in ("record", "history", "historyRevision", "destination", "requestId", "reason", "proposal", "processing"):
        if key in args:
            text(args[key], 256 if key == "historyRevision" else 2000)
    if "expectedRevision" in args and args["expectedRevision"] is not None:
        text(args["expectedRevision"], 256)
    if "processing" in args and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", args["processing"]):
        raise StoreError("Invalid processing registration identity")
    if operation == "intake.history-propose":
        if args["item"] is not None:
            check(args["item"], "item")
        if args["intent"] is not None:
            check(args["intent"], "intent")
        if (args["item"] is None) == (args["intent"] is None):
            raise StoreError("Select original intake or an explicit correction")


class IntakeOperations:
    def __init__(self, root, registration, store, *, guard):
        validate_registration(registration)
        self.root, self.registration, self.store, self.guard = root, deepcopy(registration), store, guard
        self.pending = []
        self.processing = None
        if 'processing' in registration:
            from knowledge_operation_processing import ProcessingOperations

            self.processing = ProcessingOperations(self, registration['processing'])
        store.intake_judgment_authorization = self.judgment_authorization
        store.intake_processing_reuse_selection = self.reuse_authorization

    def planner(self, actor, at, log):
        from knowledge_operations import private_path

        self.guard()
        pin = self.registration["planner"]
        private_path(self.root, pin["path"])
        read_pinned(self.root, pin)
        planner = load_planner(self.root, pin["path"], actor=actor, now=at, log=log)
        read_pinned(self.root, pin)
        if planner.boundary.policy.binding != self.store.contract.policy.binding:
            raise StoreError("Intake planner and writer policy differ")
        classifier = getattr(planner, "classifier", None)
        if classifier is not None and classifier.get("execution_mode") != "embedded":
            raise StoreError("Shared intake operations require embedded inference")
        return planner

    @staticmethod
    def no_inference(*args):
        raise StoreError("Authorization revalidation cannot perform intake work")

    def judgment_authorization(self, history, *, actor, at):
        planner = self.planner(actor, self.current_time(at), self.no_inference)
        if not callable(getattr(planner, "authorization", None)):
            raise StoreError("Projected intake requires current source authorization")
        boundary, protection = planner.authorization()
        entry = planner.catalog.entry(history["item"])
        return boundary, protection, entry

    def reuse_authorization(self, selection, *, actor, at):
        # The projected boundary already chose a fresh instant; reuse must
        # attest to that exact actor/time/bindings, not advance it independently.
        planner = self.planner(actor, at, self.no_inference)
        provider = getattr(planner, "reuse_authorization", None)
        if not callable(provider):
            raise StoreError("Processing reuse requires current host selection")
        return provider(selection, actor=actor, at=at)

    def current_time(self, not_before):
        now = self.store.intake_clock()
        if timestamp(now) < timestamp(not_before):
            raise StoreError("Intake authorization clock moved backwards")
        return now

    def validate_proposal(self, identity, *, actor, at, acknowledgement=False):
        proposal = self.store._proposal(identity, at, allow_deferred=True, allow_expired=acknowledgement)
        if acknowledgement and self.store.dialect.execute(
                'SELECT 1 FROM receipts WHERE actor=? AND request_id=?',
                (actor, proposal['request']['id'])).fetchone():
            # The native commit API verifies exact intent and current read access
            # before returning the old receipt; no new source write is authorized.
            return
        record = proposal.get('record') or {}
        data = record.get('content', {}).get('data', {})
        history = data.get('intakeHistory')
        if history is not None:
            validate_history(history)
            planner = self.planner(actor, at, self.no_inference)
            if (record['collection'] != self.registration['collection'] or planner.basis != history['basis']
                    or not planner.authorized(history['item'])):
                raise StoreError('Intake history registration or source changed')
            self.pending.append((actor, deepcopy(history['item']), deepcopy(planner.basis)))
        origin = data.get('intakeDelivery')
        if origin is not None:
            target = self.registration['destinations'].get(origin['destination']['id'])
            if target != origin['destination']['target'] or target['authority'] != self.store.contract.authority:
                raise StoreError('Intake destination registration changed')
            if origin['format'] == 'intake-processed-record/v1':
                if self.processing is None:
                    raise StoreError('Processed intake host registration required')
                self.processing.validate_proposal(origin['representation'], actor=actor, at=at)

    def execute(self, operation, args, *, actor, at):
        store = self.store
        if operation == "intake.history-propose":
            with audit(self.root) as journal:
                log = partial(log_operation, journal)
                planner = self.planner(actor, at, log)
                adapter = IntakeAuthority(store, lambda selected, now: planner,
                                          collection=self.registration["collection"])
                result = adapter.propose(args["record"], args["expectedRevision"], args["item"],
                    intent=args["intent"], actor=actor, at=at, request_id=args["requestId"], reason=args["reason"])
                proposal = store._proposal(result["proposal"], at)
                history = proposal["record"]["content"]["data"]["intakeHistory"]
                self.pending.append((actor, deepcopy(history["item"]), deepcopy(planner.basis)))
                return result
        if operation in ("intake.delivery-propose", "intake.processed-delivery-propose"):
            target = self.registration["destinations"].get(args["destination"])
            if target is None or target["authority"] != store.contract.authority:
                raise StoreError("Local intake destination unavailable")
            writer, options = store.propose_intake, {}
            if operation == 'intake.processed-delivery-propose':
                if self.processing is None:
                    raise StoreError('Processed intake host registration required')
                receipt, boundary = self.processing.load(args['processing'], actor=actor, at=at)
                writer = store.propose_processed_intake
                options = {'representation': receipt, 'expected_sha256': fingerprint(receipt), 'boundary': boundary}
            return writer(args["history"], args["historyRevision"], args["destination"],
                args["record"], target["collection"], actor, expected_revision=args["expectedRevision"],
                request_id=args["requestId"], reason=args["reason"], at=at, destination_target=target, **options)
        proposal = store._proposal(args["proposal"], at, allow_deferred=True)
        if fingerprint(proposal) != args["expectedProposalSha256"]:
            raise StoreError("Proposal changed; inspect before source review")
        if proposal.get("promotion", {}).get("projection") not in ("intake-metadata-record/v1", "intake-processed-record/v1"):
            raise StoreError("An intake delivery proposal is required")
        if operation == 'intake.source-review':
            self.validate_proposal(args['proposal'], actor=actor, at=at)
        method = store.review_source if operation == "intake.source-review" else store.revoke_source_review
        result = method(args["proposal"], actor, args["reason"], at=at)
        def recheck(now):
            current = store._proposal(args["proposal"], now, allow_deferred=True)
            store._promotion_source(current, actor, now)
            store._check_source_reviewer(current, actor, now)
        store._request_checks.append(recheck)
        return result

    def revalidate(self, at):
        for actor, item, basis in self.pending:
            planner = self.planner(actor, at, self.no_inference)
            if planner.basis != basis or not planner.authorized(item):
                raise StoreError("Intake source or policy changed before history release")
        if self.processing is not None:
            self.processing.revalidate(at)
