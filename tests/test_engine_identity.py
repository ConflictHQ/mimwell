"""Public MCP identity comes from the pinned engine, independently of the edition."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from brain_mcp import Brain, View, dispatch
from knowledge_store import Contract, SQLiteAuthority, StoreError

ROOT = Path(__file__).resolve().parents[1]


class EngineIdentity(unittest.TestCase):
    def test_mcp_initialize_reports_the_pinned_engine_version(self):
        edition = json.loads((ROOT / "edition.json").read_text())
        descriptor = json.loads((ROOT / "engine-release.json").read_text())
        self.assertEqual(descriptor, {
            "format": "public-engine-identity/v1",
            "version": edition["engineVersion"],
            "sourceCommit": edition["engineSourceCommit"],
        })
        brain = Brain(ROOT)
        result = dispatch(brain, View(brain, "fixture@example.test"), {
                                       "jsonrpc": "2.0", "id": 1, "method": "initialize",
                                       "params": {"protocolVersion": "2025-03-26"}})
        self.assertEqual(result["result"]["serverInfo"]["version"], edition["engineVersion"])
        self.assertNotEqual(edition["engineVersion"], "0")


class CoreTermCompatibility(unittest.TestCase):
    """Disposable native stores use only public schemas and synthetic policy."""

    ACTOR = "writer@example.test"
    NOW = "2026-01-02T00:00:00Z"

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.open_stores = []
        self.addCleanup(self.close_stores)
        practice = "Synthetic glossary records require independent review.\n"
        resources = (("ordinary", "glossary-entries"), ("governed", "business-terms"))
        self.bundle = {
            "contract": {
                "protocolVersion": "1.0", "id": "public-term-fixture", "version": "1.0.0",
                "authority": "canon",
                "stores": [{"id": "canon", "driver": "sqlite", "roles": ["records", "journal"]}],
                "collections": [
                    {"id": collection, "kind": "glossary-term", "resource": resource,
                     "schemaVersion": "1.0.0",
                     "fields": [{"paths": ["/content", "/relations", "/evidence"], "store": "canon"}]}
                    for collection, resource in resources
                ],
                "history": {"mode": "complete-since-import", "priorHistory": "unknown",
                            "note": "Synthetic import has no asserted earlier history."},
            },
            "ontology": json.loads((ROOT / "brain-schema.json").read_text()),
            "policy": {
                "protocolVersion": "1.0", "id": "public-term-policy", "version": "1.0.0",
                "principals": [{"id": self.ACTOR, "kind": "agent"},
                               {"id": "reviewer@example.test", "kind": "human"}],
                "scopes": [{
                    "id": "fixture", "parent": None, "space": "workspace",
                    "owner": "reviewer@example.test",
                    "practice": {"id": "synthetic", "version": "1.0.0", "path": "fixture/practice.md",
                                 "sha256": hashlib.sha256(practice.encode()).hexdigest()},
                    "rules": {"readers": [self.ACTOR, "reviewer@example.test"],
                              "proposers": [self.ACTOR], "committers": [self.ACTOR],
                              "reviewers": ["reviewer@example.test"], "fastAuto": False,
                              "separateReview": True, "allowDelete": False, "retentionDays": 30},
                }],
                "exceptions": [],
                "resources": [{"id": resource, "scope": "fixture", "kind": "glossary-term",
                               "retentionSince": "2026-01-01T00:00:00Z"}
                              for _, resource in resources],
            },
            "practices": {"fixture/practice.md": practice},
        }

    def initialize(self, records, name="authority.db"):
        store = SQLiteAuthority.initialize(self.directory / name, self.bundle, records)
        self.open_stores.append(store)
        return store

    def close_stores(self):
        for store in self.open_stores:
            store.close()

    def reopen(self, store, **options):
        store.close()
        self.open_stores.remove(store)
        reopened = SQLiteAuthority(self.directory / "authority.db", **options)
        self.open_stores.append(reopened)
        return reopened

    @staticmethod
    def term(identity, content, collection="ordinary"):
        return {"id": identity, "kind": "glossary-term", "collection": collection,
                "content": content, "relations": []}

    def test_initialized_terms_reopen_without_invented_fields_or_rewritten_text(self):
        entry = {"term": "Término", "definition": "A synthetic glossary definition.",
                 "extra": {"second": 2, "first": 1}, "aliases": ["First", "Second"]}
        text = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        records = [self.term("glossary-term:title-only", {"title": "Title only"}),
                   self.term("glossary-term:register", {"title": entry["term"], "text": text,
                                                        "data": entry})]
        store = self.initialize(records)
        binding = deepcopy(Contract(self.bundle).binding)
        snapshot = store.export()
        SQLiteAuthority.validate_snapshot(snapshot)
        reopened = self.reopen(store, expected_binding=binding)
        self.assertEqual(reopened.contract.binding, binding)
        self.assertEqual(reopened.export(), snapshot)
        for expected in records:
            observed = reopened.get(expected["id"], self.ACTOR, at=self.NOW)["record"]
            self.assertEqual(observed, expected)
            self.assertNotIn("owner", observed["content"])
        observed = reopened.get(records[1]["id"], self.ACTOR, at=self.NOW)["record"]["content"]
        self.assertEqual(observed["text"], text)
        self.assertEqual(list(json.loads(observed["text"])), list(entry))
        self.assertEqual(json.loads(observed["text"]), observed["data"])

    def test_initialized_sealed_core_term_stays_opaque(self):
        value = self.term("glossary-term:sealed", {
            "text": "enc:v1:AAECAwQFBgcICQoLDA0ODw==",
            "data": {"protected": {"format": "brain-store-seal/v1", "key": "synthetic-key"}},
            "source": {"path": "app/glossary.json", "locator": "/terms/0"},
        })
        store = self.initialize([value])
        self.assertEqual(store.get(value["id"], self.ACTOR, at=self.NOW)["record"], value)
        snapshot = store.export()
        SQLiteAuthority.validate_snapshot(snapshot)
        reopened = self.reopen(store)
        self.assertEqual(reopened.export(), snapshot)
        self.assertEqual(reopened.get(value["id"], self.ACTOR, at=self.NOW)["record"], value)

    def test_explicit_business_resource_still_requires_owner_before_native_effects(self):
        valid = self.term("glossary-term:governed", {
            "title": "Governed term", "text": "A synthetic business definition.",
            "owner": "synthetic-owner", "data": {"aliases": [], "governsMetrics": []},
        }, "governed")
        store = self.initialize([valid])
        snapshot = store.export()
        invalid = deepcopy(valid)
        invalid["id"] = "glossary-term:missing-owner"
        del invalid["content"]["owner"]
        with self.assertRaisesRegex(StoreError, "business term requires"):
            SQLiteAuthority.initialize(self.directory / "invalid.db", self.bundle, [invalid])
        self.assertFalse((self.directory / "invalid.db").exists())
        request = {"id": "missing-owner", "record": invalid["id"], "resource": "business-terms",
                   "mutation": "create", "expectedRevision": None, "reason": "Synthetic schema check",
                   "evidence": ["claim.synthetic-owner-fixture"], "sourceResource": None}
        with self.assertRaisesRegex(StoreError, "business term requires"):
            store.propose(request, invalid, self.ACTOR, at=self.NOW)
        self.assertEqual(store.export(), snapshot)
