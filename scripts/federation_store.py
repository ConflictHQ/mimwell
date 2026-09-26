"""Source-authorized federation snapshots of a live SQLite knowledge authority."""
import sqlite3

from brain_federation import FederationError
from federation_resolution import LocalRecordSource
from knowledge_policy import fingerprint
from knowledge_store import SQLiteAuthority


class SQLiteRecordSource(LocalRecordSource):
    """Read once per authenticated host request; release checks remain independent.

    The database connection closes before resolution. This source represents its
    consistent read point, not a promise that the authority cannot later change.
    """

    def __init__(self, *, path, expected_binding, participant, authority, boundary,
                 consumer, publications, composition=False, references=None, protection=None):
        try:
            store = SQLiteAuthority(path, expected_binding=expected_binding, readonly=True)
            try:
                if store.contract.policy.binding != boundary.policy.binding:
                    raise FederationError("Source policy or ontology differs from the authority contract")
                snapshot = store.read_snapshot(boundary.actor, at=boundary.now)
            finally:
                store.close()
        except sqlite3.Error as exc:
            raise FederationError("Structured authority is unavailable") from exc
        if snapshot["checkpoint"]["state"] != "active":
            raise FederationError("Federation requires an active structured authority")
        for identity, resource in snapshot["resources"].items():
            declared = boundary.bindings["nodes"].get(identity)
            if declared is not None and declared != resource:
                raise FederationError("Source node binding differs from its governed collection")
        super().__init__(participant=participant, realm="brain", authority=authority,
                         records=snapshot["graph"]["nodes"], boundary=boundary,
                         consumer=consumer, publications=publications, protection=protection)
        self._composition = composition
        if type(composition) is not bool:
            raise FederationError("Composition must be explicitly selected")
        if composition:
            from federation_composition import LocalGraphSource
            LocalGraphSource._configure_graph(self, snapshot["graph"]["edges"], {} if references is None else references)
        elif references is not None:
            raise FederationError("Record-only source cannot configure graph references")
        graph_revision = self._revision
        self._checkpoint = fingerprint(snapshot["checkpoint"])
        self._contract_binding = snapshot["checkpoint"]["binding"]
        self._record_revisions = snapshot["revisions"]
        self._revision = fingerprint({"checkpoint": self._checkpoint, "records": self._records,
                                      "revisions": self._record_revisions})

        if composition:
            self._revision = fingerprint({"authority": self._revision, "graph": graph_revision})

    def snapshot(self, **options):
        from federation_composition import LocalGraphSource
        from federation_resolution import unavailable
        if not self._composition:
            return unavailable("unsupported-contract")
        return LocalGraphSource.snapshot(self, **options)

    def resolve(self, address, **options):
        result = super().resolve(address, **options)
        if result["status"] == "resolved":
            result["provenance"]["store"] = {
                "kind": "sqlite-authority", "bindingSha256": self._contract_binding,
                "snapshotSha256": self._checkpoint, "state": "active",
                "recordRevision": self._record_revisions[address],
            }
        return result

    def _revalidate_edge(self, row, options):
        from federation_composition import LocalGraphSource
        if not self._composition:
            return super()._revalidate_edge(row, options)
        return LocalGraphSource._revalidate_edge(self, row, options)
