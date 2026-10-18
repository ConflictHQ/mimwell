"""Public MCP identity comes from the pinned engine, independently of the edition."""
import json
from pathlib import Path
import unittest

from brain_mcp import Brain, View, dispatch

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
