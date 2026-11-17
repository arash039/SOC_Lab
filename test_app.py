#!/usr/bin/env python3
"""Unit tests for the SOC Lab backend. Run: attack_data/venv/bin/python soc_lab/test_app.py"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import app  # noqa: E402

PROJECT = Path(__file__).resolve().parent.parent


class LegacyYamlTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.root = Path(self._tmp.name)
        self.datasets = self.root / "datasets" / "attack_techniques" / "T1003.001" / "demo"
        self.datasets.mkdir(parents=True)
        self.patch = mock.patch.multiple(
            app, ATTACK_DATA=self.root, DATASETS_DIR=self.root / "datasets"
        )
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def test_sniff_xml_channel_wins_over_hint(self):
        path = self.datasets / "windows-sysmon.log"
        path.write_text(
            "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
            "<System><Channel>Microsoft-Windows-Sysmon/Operational</Channel></System></Event>"
        )
        sourcetype, source = app.infer_legacy_metadata(path, "xmlwineventlog")
        self.assertEqual(sourcetype, "XmlWinEventLog")
        self.assertEqual(source, "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational")

    def test_plain_windows_hint(self):
        path = self.datasets / "windows-security.log"
        path.write_text("09/18/2020 10:00:00 AM\nEventCode=4624\n")
        sourcetype, source = app.infer_legacy_metadata(path, "WinEventLog:Security")
        self.assertEqual(sourcetype, "WinEventLog:Security")
        self.assertEqual(source, "WinEventLog:Security")

    def test_legacy_entries_maps_github_url_to_local_file(self):
        path = self.datasets / "demo.log"
        path.write_text("<Event><System><Channel>Security</Channel></System></Event>")
        doc = {
            "id": "11111111-1111-1111-1111-111111111111",
            "dataset": [
                "https://media.githubusercontent.com/media/splunk/attack_data/master/"
                "datasets/attack_techniques/T1003.001/demo/demo.log"
            ],
            "sourcetypes": ["xmlwineventlog"],
        }
        entries = app.legacy_entries(doc)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["path"], str(path.resolve()))
        self.assertEqual(entries[0]["sourcetype"], "XmlWinEventLog")
        self.assertEqual(entries[0]["source"], "XmlWinEventLog:Security")

    def test_legacy_entries_skips_missing_files(self):
        doc = {"dataset": ["https://example.com/master/datasets/attack_techniques/T1/nope.log"]}
        self.assertEqual(app.legacy_entries(doc), [])


class PathSafetyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.root = Path(self._tmp.name)
        self.datasets = self.root / "datasets"
        (self.datasets / "attack_techniques" / "T1003.001" / "demo").mkdir(parents=True)
        self.patch = mock.patch.object(app, "DATASETS_DIR", self.datasets)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def test_valid_folder(self):
        path = app.safe_dataset_dir("attack_techniques/T1003.001/demo")
        self.assertTrue(path.is_dir())

    def test_rejects_traversal(self):
        with self.assertRaises(ValueError):
            app.safe_dataset_dir("../../etc")
        with self.assertRaises(ValueError):
            app.safe_dataset_dir("/etc")


class FieldConfigTests(unittest.TestCase):
    def test_merge_props_adds_stanza_and_is_idempotent(self):
        merged = app.merge_props("")
        self.assertIn("[XmlWinEventLog]", merged)
        self.assertIn("REPORT-soc_attack_xml", merged)
        self.assertEqual(app.merge_props(merged), merged)

    def test_merge_props_inserts_into_existing_stanza(self):
        existing = "[XmlWinEventLog]\nSHOULD_LINEMERGE = false\n\n[other]\nA = b\n"
        merged = app.merge_props(existing)
        self.assertIn("REPORT-soc_attack_xml", merged)
        self.assertIn("[other]", merged)
        self.assertEqual(merged.count("[XmlWinEventLog]"), 1)


class RecipesTests(unittest.TestCase):
    def test_recipes_are_well_formed(self):
        recipes = json.loads((PROJECT / "soc_lab" / "recipes.json").read_text())
        ids = set()
        for phase in recipes:
            self.assertTrue(phase.get("phase"))
            for recipe in phase["recipes"]:
                self.assertTrue(recipe["spl"].strip())
                self.assertIn("index=attack_data", recipe["spl"])
                self.assertNotIn(recipe["id"], ids)
                ids.add(recipe["id"])
        self.assertGreater(len(ids), 10)


class BootstrapTests(unittest.TestCase):
    def test_scan_is_empty_when_checkout_is_missing(self):
        with mock.patch.object(app, "DATASETS_DIR", Path("/tmp/opencode/does-not-exist")):
            scan = app.build_scan()
        self.assertEqual(scan["groups"], [])
        self.assertEqual(scan["by_path"], {})

    def test_repo_status_reports_missing_checkout(self):
        with mock.patch.multiple(
            app,
            DATASETS_DIR=Path("/tmp/opencode/does-not-exist"),
            ATTACK_DATA=Path("/tmp/opencode/does-not-exist"),
            LOCAL_ATTACK_DATA=Path("/tmp/opencode/also-missing"),
            LAB_ROOT=Path("/tmp/opencode"),
        ):
            status = app.repo_status()
        self.assertFalse(status["ready"])
        self.assertEqual(status["url"], app.REPO_URL)


if __name__ == "__main__":
    unittest.main(verbosity=2)
