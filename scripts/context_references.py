"""Host-bound reference routes for the bounded context compiler (#55/#60)."""
from copy import deepcopy

from brain_federation import fields, text
from context_bundle import ContextError
from federation_resolution import FederationResolver, ResolutionBudgetError
from knowledge_policy import fingerprint


class ReferencePlan:
    """Explicit legacy-address mapping; no inference from repository names."""

    def __init__(self, resolver, *, routes):
        if not isinstance(resolver, FederationResolver) or not isinstance(routes, dict):
            raise ContextError("Invalid context reference configuration")
        for address, target in routes.items():
            text(address)
            fields(target, ("participant", "realm", "address", "revision"))
            for value in target.values():
                text(value)
        # A caller changing its catalog or source registry cannot silently alter
        # a context's already-published request basis.
        self._resolver = deepcopy(resolver)
        self._routes = deepcopy(routes)

    def scoped(self, boundary, allowed):
        if self._resolver.authorization != {"principal": boundary.actor, "evaluatedAt": boundary.now}:
            raise ContextError("Reference resolver authorization differs from context")
        routes = {address: target for address, target in self._routes.items()
                  if address in allowed and boundary.permits("references", address)}
        return ReferenceView(self._resolver, routes)


class ReferenceView:
    def __init__(self, resolver, routes):
        self._resolver = resolver
        self._routes = deepcopy(routes)
        self.binding = fingerprint({address: {"target": target, "basis": resolver.target_basis(target)}
                                    for address, target in sorted(routes.items())})

    def resolve(self, address, *, max_bytes):
        return next(self.resolve_many([address], max_bytes=max_bytes))

    def resolve_many(self, addresses, *, max_bytes):
        """Reauthorize peers together, then yield independent aliases one at a time."""
        targets = [self._routes[address] for address in addresses if address in self._routes]
        try:
            response = (self._resolver.resolve({"protocolVersion": "1.0", "targets": targets,
                "budget": {"maxTargets": len(targets), "maxBytes": max_bytes}}) if targets else {'results': []})
        except ResolutionBudgetError:
            response = {"results": []}
        outcomes = {fingerprint(row['target']): row for row in response['results']}
        for address in addresses:
            target = self._routes.get(address)
            if target is None:
                yield {'address': address, 'status': 'unavailable', 'reason': 'offline'}
                continue
            outcome = outcomes.get(fingerprint(target))
            if (outcome is None or
                    (outcome['status'] == 'unavailable' and outcome.get('reason') == 'maxBytes')):
                # Keep the compact budget-gap shape whether staging refused the
                # row or the aggregate envelope could not hold it.
                yield {'address': address, 'status': 'unavailable', 'reason': 'maxBytes'}
            else:
                yield {'address': address, **deepcopy(outcome)}
