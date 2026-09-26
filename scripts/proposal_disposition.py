"""Native proposal decisions; never a second canonical record writer."""

from copy import deepcopy

from knowledge_policy import PolicyError, fingerprint, timestamp
from knowledge_store import StoreError

ACTIONS = {"approve": "approved", "reject": "rejected", "defer": "deferred", "withdraw": "withdrawn"}
CLOSED = {"rejected", "withdrawn"}
MAX_EVENTS = 256
MAX_REASON = 2000
REVIEW_FIELDS = ("review", "sourceReview", "sourceRevocation")


def intent(proposal):
    return fingerprint(
        {
            "request": proposal["request"],
            "record": proposal["record"],
            "proposer": proposal["actor"],
            "contract": proposal["contract"],
        }
    )


def state(proposal):
    """Validate the bounded chain before relying on a proposal's lifecycle."""
    history = proposal.get("dispositionHistory", [])
    if not isinstance(history, list) or len(history) > MAX_EVENTS:
        raise StoreError("Invalid proposal disposition history")
    previous, at, current = None, timestamp(proposal["at"]), "pending"
    expected_intent = intent(proposal)
    for sequence, event in enumerate(history, 1):
        if not isinstance(event, dict) or set(event) != {
            "format",
            "proposal",
            "intentSha256",
            "sequence",
            "previous",
            "action",
            "actor",
            "reason",
            "at",
            "proposalSha256",
            "priorReviews",
            "sha256",
        }:
            raise StoreError("Invalid proposal disposition event")
        digest = fingerprint({k: v for k, v in event.items() if k != "sha256"})
        if (
            current in CLOSED
            or event["format"] != "proposal-disposition/v1"
            or event["proposal"] != proposal["id"]
            or event["intentSha256"] != expected_intent
            or type(event["sequence"]) is not int
            or event["sequence"] != sequence
            or event["previous"] != previous
            or event["sha256"] != digest
            or not isinstance(event["action"], str)
            or event["action"] not in ACTIONS
            or not isinstance(event["actor"], str)
            or not event["actor"].strip()
            or not isinstance(event["reason"], str)
            or (not event["reason"].strip() or len(event["reason"]) > MAX_REASON)
            or not isinstance(event["proposalSha256"], str)
            or len(event["proposalSha256"]) != 64
            or any(c not in "0123456789abcdef" for c in event["proposalSha256"])
            or timestamp(event["at"]) < at
        ):
            raise StoreError("Corrupt proposal disposition history")
        prior = event["priorReviews"]
        if not isinstance(prior, dict) or "review" not in prior or set(prior) - set(REVIEW_FIELDS):
            raise StoreError("Invalid prior proposal review basis")
        basis = {
            key: deepcopy(value) for key, value in proposal.items() if key not in (*REVIEW_FIELDS, "dispositionHistory")
        }
        basis.update(deepcopy(prior))
        if sequence > 1:
            basis["dispositionHistory"] = history[: sequence - 1]
            last_event = history[sequence - 2]
            expected = (
                {key: last_event[key] for key in ("actor", "reason", "at")}
                if last_event["action"] == "approve"
                else None
            )
            if prior["review"] != expected:
                raise StoreError("Prior review differs from the disposition chain")
        if fingerprint(basis) != event["proposalSha256"]:
            raise StoreError("Disposition basis differs from its prior proposal")
        for review in prior.values():
            if review is not None and (
                not isinstance(review, dict)
                or set(review) != {"actor", "reason", "at"}
                or timestamp(review["at"]) > timestamp(event["at"])
            ):
                raise StoreError("Invalid historical review basis")
        current, at, previous = ACTIONS[event["action"]], timestamp(event["at"]), digest
    if history:
        expected_review = (
            {key: history[-1][key] for key in ("actor", "reason", "at")} if current == "approved" else None
        )
        if proposal["review"] != expected_review:
            raise StoreError("Proposal approval disagrees with its disposition")
    elif proposal.get("review") is not None:
        current = "approved"  # Existing approvals retain their native history limits.
    return current


def commitment(proposal, receipts):
    """New receipts identify the proposal. Old intent-only receipts stay unattributed."""
    legacy = False
    for receipt in receipts:
        if receipt.get("proposal") == proposal["id"]:
            if (
                receipt["request"] != proposal["request"]
                or receipt["after"] != proposal["record"]
                or receipt["proposedBy"] != proposal["actor"]
                or receipt["contract"] != proposal["contract"]
                or receipt["review"] != proposal["review"]
                or any(receipt.get(key) != proposal.get(key) for key in ("promotion", "sourceReview", "transfer"))
                or timestamp(receipt["at"]) < timestamp(proposal["at"])
                or any(
                    timestamp(event["at"]) > timestamp(receipt["at"])
                    for event in proposal.get("dispositionHistory", [])
                )
            ):
                raise StoreError("Commit receipt differs from its proposal")
            return "committed"
        if "proposal" not in receipt:
            legacy = True
    return "committed-unattributed" if legacy else None


def committed(store, proposal):
    import json

    budget = getattr(store, "_inspection_budget", None)
    rows = (budget.receipts(store.db, intent(proposal)) if budget is not None else
            store.db.execute("SELECT body FROM receipts WHERE intent=?", (intent(proposal),)))
    receipts = [json.loads(row[0]) for row in rows]
    return commitment(proposal, receipts)


def observation(store, proposal):
    current = state(proposal)
    result = committed(store, proposal)
    if result:
        if current in CLOSED or current == "deferred":
            raise StoreError("Committed proposal has an incompatible disposition")
        current = result
    return {
        "state": current,
        "historyBasis": "recorded-disposition-events; earlier approval history may be unknown",
        "events": len(proposal.get("dispositionHistory", [])),
    }


def append(proposal, action, actor, reason, at, basis):
    current = state(proposal)
    history = proposal.get("dispositionHistory", [])
    times = [proposal["at"], *([history[-1]["at"]] if history else [])]
    times += [proposal[key]["at"] for key in ("review", "sourceReview", "sourceRevocation") if proposal.get(key)]
    last = max(timestamp(value) for value in times)
    if (
        current in CLOSED
        or action not in ACTIONS
        or len(history) >= MAX_EVENTS
        or not isinstance(reason, str)
        or (not reason.strip() or len(reason) > MAX_REASON)
        or timestamp(at) < last
    ):
        raise StoreError("Invalid or closed proposal disposition")
    event = {
        "format": "proposal-disposition/v1",
        "proposal": proposal["id"],
        "intentSha256": intent(proposal),
        "sequence": len(history) + 1,
        "previous": history[-1]["sha256"] if history else None,
        "action": action,
        "actor": actor,
        "reason": reason,
        "at": at,
        "proposalSha256": basis,
        "priorReviews": {key: deepcopy(proposal[key]) for key in REVIEW_FIELDS if key in proposal},
    }
    event["sha256"] = fingerprint(event)
    proposal["dispositionHistory"] = [*history, event]
    proposal["review"] = {key: event[key] for key in ("actor", "reason", "at")} if action == "approve" else None
    return deepcopy(event)


def approve(store, proposal, actor, reason, at):
    if committed(store, proposal):
        raise StoreError("Proposal intent is already committed")
    return append(proposal, "approve", actor, reason, at, fingerprint(proposal))


def authorize_disposition(contract, proposal, actor, action, at):
    """Current declared roles authorize cancelling/holding, not a record mutation.

    Stale revisions, expiry or a changed retention age do not prevent closing
    obsolete work. Approval/commit still pass the unchanged mutation policy.
    """
    policy = contract.policy
    resource = policy.resources.get(proposal["request"]["resource"])
    if resource is None or actor not in policy.principals:
        raise PolicyError("Proposal disposition authority denied")
    rules, _, _ = policy.effective(resource["scope"], timestamp(at))
    if actor not in rules["readers"]:
        raise PolicyError("Proposal disposition read access denied")
    if action == "withdraw":
        if actor != proposal["actor"] or actor not in rules["proposers"]:
            raise PolicyError("Withdrawal requires the original authorized proposer")
    else:
        if actor not in rules["reviewers"] or rules["separateReview"] and actor == proposal["actor"]:
            raise PolicyError("Proposal disposition requires an eligible independent reviewer")
        slow = policy.kinds[resource["kind"]] == "slow" or proposal["request"]["mutation"] in (
            "supersede",
            "retract",
            "delete",
            "promote",
        )
        if slow and policy.principals[actor]["kind"] != "human":
            raise PolicyError("Slow-tier disposition requires a human reviewer")


def dispose(store, identity, actor, action, reason, *, expected_proposal_sha256, at):
    if action not in ("reject", "defer", "withdraw"):
        raise StoreError("Unsupported proposal disposition")
    with store.transaction():
        inspected = store.inspect(identity, actor, at=at)
        proposal = inspected["proposal"]
        if inspected["proposalSha256"] != expected_proposal_sha256:
            raise StoreError("Proposal changed; inspect its current intent before deciding")
        if inspected["lifecycle"]["state"] in ("committed", "committed-unattributed"):
            raise StoreError("Proposal intent is already committed")
        authorize_disposition(store.contract, proposal, actor, action, at)
        if getattr(store, "_request_write", False):
            captured = deepcopy(proposal)

            def recheck(now):
                store.inspect(identity, actor, at=now)
                authorize_disposition(store.contract, captured, actor, action, now)

            store._request_checks.append(recheck)
        receipt = append(proposal, action, actor, reason, at, expected_proposal_sha256)
        from knowledge_store import encoded

        store.db.execute("UPDATE proposals SET body=? WHERE id=?", (encoded(proposal), identity))
        return receipt


def validate_history(contract, proposal):
    """Replay declared authority at event time, without live source dependencies."""
    current = state(proposal)
    # A proposal stored before schema 11 keeps the driver-inclusive binding it was made under.
    if proposal["contract"] != contract.binding and proposal["contract"] not in contract.legacy_bindings:
        raise StoreError("Proposal references a different authority contract")
    for event in proposal.get("dispositionHistory", []):
        authorize_disposition(contract, proposal, event["actor"], event["action"], event["at"])
        if event["action"] == "approve" and timestamp(event["at"]) >= timestamp(proposal["expiresAt"]):
            raise StoreError("Historical approval follows proposal expiry")
    return current
