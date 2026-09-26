"""Portable empty-portal/runtime smoke tests without private examples or receipts."""
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator

from ontology import Registry
from knowledge_policy import fingerprint
import knowledge_operations
import intake_host
import context_host

ROOT = Path(__file__).resolve().parents[1]


class PublicSmoke(unittest.TestCase):
    def test_empty_register_seeds_match_their_declared_schema(self):
        for artifact in (ROOT / "app").glob("*.json"):
            schema = ROOT / "schemas" / (artifact.stem + ".schema.json")
            if schema.exists() and artifact.name != "brain.json":
                with self.subTest(artifact=artifact.name):
                    validator = Draft202012Validator(json.loads(schema.read_text()))
                    self.assertEqual(list(validator.iter_errors(json.loads(artifact.read_text()))), [])

    def test_compiled_empty_graph_and_registry_binding(self):
        declaration = json.loads((ROOT / "brain-schema.json").read_text())
        graph = json.loads((ROOT / "app/brain.json").read_text())
        Registry(declaration).validate_graph(graph, require_binding=True)
        self.assertEqual(graph["nodes"], [])
        self.assertEqual(graph["edges"], [])

    def test_runtime_imports_and_deterministic_fingerprints(self):
        self.assertIn("record.get", knowledge_operations.ARGUMENTS)
        self.assertTrue(callable(intake_host.load_planner))
        self.assertTrue(callable(context_host.load_boundary))
        self.assertEqual(fingerprint({"a": 1, "b": 2}), fingerprint({"b": 2, "a": 1}))

    def test_every_selected_portal_page_exists(self):
        config = json.loads((ROOT / "client.config.json").read_text())
        for page in config["pages"]:
            url = page["url"]
            file = ROOT / (url.lstrip("/") + ("index.html" if url.endswith("/") else ""))
            self.assertTrue(file.is_file(), url)

    def test_worker_and_package_branding_are_consistent(self):
        config = json.loads((ROOT / "client.config.json").read_text())
        expected = config["client"]["slug"] + "-portal"
        self.assertEqual(json.loads((ROOT / "package.json").read_text())["name"], expected)
        lock = json.loads((ROOT / "package-lock.json").read_text())
        self.assertEqual(lock["name"], expected)
        self.assertEqual(lock["packages"][""]["name"], expected)
        self.assertIn(f'name = "{expected}"', (ROOT / "wrangler.toml").read_text())

    def test_catalog_claims_no_private_evidence(self):
        self.assertFalse((ROOT / "recipes/catalog.json").exists())
        for folder in ("proofs", "practices", ".claude", ".codex", "memory"):
            self.assertFalse((ROOT / folder).exists())
