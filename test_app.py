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

    def test_strip_field_props_removes_lab_config_only(self):
        lab = app.FIELD_PROPS.read_text()
        self.assertEqual(app.strip_field_props(lab), "")
        existing = (
            "[XmlWinEventLog]\nSHOULD_LINEMERGE = false\n"
            "REPORT-soc_attack_xml = a, b\n\n[other]\nA = b\n"
        )
        stripped = app.strip_field_props(existing)
        self.assertIn("SHOULD_LINEMERGE = false", stripped)
        self.assertIn("[other]", stripped)
        self.assertNotIn("REPORT-soc_attack_xml", stripped)

    def test_strip_field_transforms_removes_lab_stanzas(self):
        lab = app.FIELD_TRANSFORMS.read_text()
        self.assertEqual(app.strip_field_transforms(lab), "")
        self.assertIn("soc_attack_xml_eventid", lab)


class DeleteHelperTests(unittest.TestCase):
    def test_local_data_files_excludes_yaml(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as tmp:
            folder = Path(tmp)
            (folder / "data.log").write_text("<Event/>")
            (folder / "events.json").write_text("{}")
            (folder / "notes.yml").write_text("id: x")
            (folder / "readme.md").write_text("x")
            (folder / "sub").mkdir()
            names = [path.name for path in app.local_data_files(folder)]
        self.assertEqual(names, ["data.log", "events.json"])

    def test_format_bytes(self):
        self.assertEqual(app.format_bytes(0), "0 B")
        self.assertEqual(app.format_bytes(1536), "1.5 KB")
        self.assertEqual(app.format_bytes(12 * 1024 * 1024), "12 MB")


class ScenarioTests(unittest.TestCase):
    def sample(self):
        return {
            "schema_version": 1,
            "id": "demo-001",
            "title": "Demo",
            "summary": "Summary",
            "briefing": "Briefing",
            "dataset": {
                "repo": "https://github.com/splunk/attack_data.git",
                "path": "attack_techniques/T1003.001/demo",
                "techniques": ["T1003.001"],
                "required_fields": ["EventCode"],
            },
            "stages": [
                {
                    "id": "orient",
                    "title": "Orient",
                    "narrative": "Look around.",
                    "question": "Which source?",
                    "answer": {"type": "choice", "options": ["a", "b"], "correct": 1},
                    "debrief": "b",
                }
            ],
            "debrief": "Done.",
        }

    def test_shipped_scenarios_are_valid(self):
        docs = app.load_scenarios()
        self.assertIn("t1003-001-credential-dumping-on-a-windows-host", docs)
        for doc in docs.values():
            app.validate_scenario(doc)

    def test_rejects_bad_choice_index(self):
        doc = self.sample()
        doc["stages"][0]["answer"]["correct"] = 5
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)

    def test_rejects_duplicate_stage_ids(self):
        doc = self.sample()
        doc["stages"].append(dict(doc["stages"][0]))
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)

    def test_rejects_dataset_traversal(self):
        doc = self.sample()
        doc["dataset"]["path"] = "../outside"
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)

    def test_rejects_missing_or_unsafe_repo(self):
        doc = self.sample()
        del doc["dataset"]["repo"]
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)
        doc = self.sample()
        doc["dataset"]["repo"] = "file:///etc"
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)

    def test_rejects_unknown_check_type(self):
        doc = self.sample()
        doc["stages"][0]["checks"] = [{"type": "evidence"}]
        with self.assertRaises(ValueError):
            app.validate_scenario(doc)

    def test_broken_scenario_is_hidden(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as tmp:
            folder = Path(tmp)
            (folder / "good.json").write_text(json.dumps(self.sample()))
            bad = self.sample()
            bad["id"] = "bad-001"
            bad["stages"][0]["checks"] = [{"type": "nope"}]
            (folder / "bad.json").write_text(json.dumps(bad))
            with mock.patch.object(app, "SCENARIOS_DIR", folder):
                docs = app.load_scenarios()
        self.assertIn("demo-001", docs)
        self.assertNotIn("bad-001", docs)

    def test_public_view_hides_checks_and_answers(self):
        doc = app.load_scenarios()["t1003-001-credential-dumping-on-a-windows-host"]
        public = app.public_scenario(doc, {"completed": []})
        text = json.dumps(public)
        self.assertNotIn('"checks"', text)
        self.assertNotIn('"accepted"', text)
        self.assertNotIn('"correct"', text)
        self.assertNotIn("lsass_dump.dmp", text)
        self.assertNotIn("starter_spl", text)
        self.assertEqual(public["debrief"], "")
        self.assertTrue(all("debrief" not in stage for stage in public["stages"]))

    def test_public_view_includes_debrief_when_complete(self):
        doc = app.load_scenarios()["t1003-001-credential-dumping-on-a-windows-host"]
        public = app.public_scenario(doc, {"completed": []}, include_debrief=True)
        self.assertIn("Verdict: true positive", public["debrief"])

    def test_expect_holds_tolerates_duplicate_rows(self):
        expect = {
            "min_rows": 1,
            "contains": {"sources": ["sysmon", "crowdstrike"]},
            "regex": {"cmd": "lsass_dump\\.dmp"},
        }
        row = {
            "sources": ["Sysmon", "CrowdStrike"],
            "cmd": ["procdump -ma lsass.exe C:\\Windows\\Temp\\lsass_dump.dmp"],
        }
        self.assertTrue(app.expect_holds([row], expect))
        self.assertTrue(app.expect_holds([row, dict(row), dict(row)], expect))
        self.assertFalse(app.expect_holds([], expect))
        self.assertFalse(app.expect_holds([{**row, "sources": ["Sysmon"]}], expect))

    def test_answer_normalizes_paths_and_exe_suffix(self):
        spec = {"type": "answer", "accepted": ["procdump.exe"]}
        self.assertTrue(app.answer_matches(spec, "C:\\AtomicRedTeam\\bin\\procdump.exe"))
        self.assertTrue(app.answer_matches(spec, "procdump"))
        self.assertFalse(app.answer_matches(spec, "notprocdump.exe"))
        dump = {"type": "answer", "accepted": ["lsass_dump.dmp"]}
        self.assertTrue(app.answer_matches(dump, "C:\\Windows\\Temp\\lsass_dump.dmp"))
        self.assertFalse(app.answer_matches(dump, ""))

    def test_hidden_search_error_does_not_leak_spl(self):
        check = {
            "type": "search",
            "spl": 'index=attack_data host="<HOST>" | stats count',
            "expect": {"min_rows": 1},
        }
        error = app.SplunkError('Error in "search index=attack_data | stats count": bad')
        with mock.patch.object(app, "splunk_search", side_effect=error):
            result = app.grade_check(check, "host-1", {})
        self.assertFalse(result["passed"])
        self.assertNotIn("stats count", result["message"])

    def test_review_does_not_block(self):
        stage = {
            "id": "verdict",
            "checks": [{"type": "review", "min_length": 10}],
        }
        passed, results = app.grade_stage({}, stage, "host-1", {"review": ""})
        self.assertTrue(passed)
        self.assertTrue(results[0]["passed"])

    def test_student_spl_check_runs_submitted_query(self):
        check = {"type": "spl", "spl": "unused", "expect": {"min_rows": 1}}
        fake = {"rows": [{"host": "host-1"}], "fields": ["host"]}
        with mock.patch.object(app, "splunk_search", return_value=fake) as run:
            result = app.grade_check(
                check, "host-1", {"spl": "index=attack_data | stats count by host"}
            )
        run.assert_called_once_with(
            "index=attack_data | stats count by host", earliest="0", limit=200
        )
        self.assertTrue(result["passed"])

    def test_hidden_search_is_scoped_to_host(self):
        check = {
            "type": "search",
            "spl": 'index=attack_data host="<HOST>" | stats count',
            "expect": {"min_rows": 1},
        }
        fake = {"rows": [{"count": "1"}], "fields": ["count"]}
        with mock.patch.object(app, "splunk_search", return_value=fake) as run:
            app.grade_check(check, "host-1", {})
        self.assertIn('host="host-1"', run.call_args[0][0])


class ScenarioPreflightTests(unittest.TestCase):
    def setUp(self):
        self.doc = {
            "id": "demo-001",
            "dataset": {"path": "attack_techniques/T1003.001/demo", "required_fields": ["EventCode"]},
        }
        self.group = {
            "state": "ready",
            "ready_files": 1,
            "file_count": 1,
            "local_files": ["demo.log"],
            "host_list": ["host-1"],
        }

    def run_preflight(self, events):
        response = mock.Mock(status_code=200)
        with mock.patch.multiple(
            app,
            DATASETS_DIR=Path("/tmp/opencode"),
            get_scan=mock.Mock(return_value={"by_path": {self.doc["dataset"]["path"]: self.group}}),
            splunk_request=mock.Mock(return_value=response),
            required_fields_status=mock.Mock(return_value=(True, "ok")),
            event_count=mock.Mock(return_value=events),
        ):
            return app.scenario_preflight(self.doc)

    def test_ready_when_dataset_events_and_fields_exist(self):
        preflight = self.run_preflight(10)
        self.assertTrue(preflight["ready"])
        self.assertEqual(preflight["host"], "host-1")

    def test_missing_events_blocks_and_offers_replay(self):
        preflight = self.run_preflight(0)
        self.assertFalse(preflight["ready"])
        step = next(item for item in preflight["steps"] if item["id"] == "events")
        self.assertEqual(step["action"], "replay")
        self.assertEqual(step["target"], self.doc["dataset"]["path"])


class ScenarioLoadTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.folder = Path(self._tmp.name)
        self.patch = mock.patch.object(app, "SCENARIOS_DIR", self.folder)
        self.patch.start()

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def sample(self):
        return ScenarioTests.sample(self)

    def test_saves_a_new_scenario_and_loads_it(self):
        result = app.save_scenario_file("T1000-Demo.json", self.sample())
        self.assertEqual(result["id"], "demo-001")
        self.assertEqual(result["filename"], "T1000-Demo.json")
        self.assertIn("demo-001", app.load_scenarios())
        self.assertTrue((self.folder / "T1000-Demo.json").is_file())

    def test_rejects_paths_duplicate_ids_and_existing_files(self):
        app.save_scenario_file("T1000-Demo.json", self.sample())
        with self.assertRaises(ValueError):
            app.save_scenario_file("../evil.json", self.sample())
        with self.assertRaises(ValueError):
            app.save_scenario_file("Other.json", self.sample())
        other = self.sample()
        other["id"] = "demo-002"
        with self.assertRaises(ValueError):
            app.save_scenario_file("T1000-Demo.json", other)
        with self.assertRaises(ValueError):
            app.save_scenario_file("Bad.json", {"id": "demo-003"})


class ScenarioSetupTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.root = Path(self._tmp.name)
        self.rel = "attack_techniques/T1003.001/demo"
        self.doc = {
            "title": "Demo scenario",
            "dataset": {
                "repo": "https://github.com/splunk/attack_data.git",
                "path": self.rel,
            },
        }
        self.group = {"host_list": ["host-1"]}
        self.replayed = False

    def tearDown(self):
        self._tmp.cleanup()

    def run_setup(self, datasets_dir, existing_events):
        def replay(job):
            self.replayed = True

        downloads = []
        make_repo = mock.Mock(return_value=lambda job: None)
        wait_events = mock.Mock(return_value=existing_events)
        with mock.patch.multiple(
            app,
            DATASETS_DIR=datasets_dir,
            ATTACK_DATA=self.root,
            splunk_request=mock.Mock(return_value=mock.Mock(status_code=200)),
            docker_status=mock.Mock(return_value={"running": True}),
            get_scan=mock.Mock(return_value={"by_path": {self.rel: self.group}}),
            event_count=mock.Mock(return_value=existing_events),
            fields_installed=mock.Mock(return_value=True),
            wait_for_host_events=wait_events,
            make_repo_runner=make_repo,
            make_download_runner=mock.Mock(
                side_effect=lambda rel: (lambda job: downloads.append(rel))
            ),
            make_replay_runner=mock.Mock(return_value=replay),
        ):
            job = app.Job("setup", "setup")
            app.make_scenario_setup_runner(self.doc)(job)
        return make_repo, wait_events, downloads, job

    def test_setup_clones_from_json_repo_and_skips_existing_replay(self):
        make_repo, _, downloads, _ = self.run_setup(self.root / "missing", 5)
        make_repo.assert_called_once_with(self.doc["dataset"]["repo"])
        self.assertEqual(downloads, [self.rel])
        self.assertFalse(self.replayed)

    def test_setup_replays_when_host_has_no_events(self):
        datasets = self.root / "datasets"
        datasets.mkdir()
        _, wait_events, _, _ = self.run_setup(datasets, 0)
        self.assertTrue(self.replayed)
        wait_events.assert_called_once()


class ScenarioProgressTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.root = Path(self._tmp.name)
        self.patch = mock.patch.multiple(
            app, STATE_DIR=self.root, PROGRESS_FILE=self.root / "scenarios.json"
        )
        self.patch.start()
        self.doc = {"id": "demo-001", "stages": [{"id": "a"}, {"id": "b"}]}

    def tearDown(self):
        self.patch.stop()
        self._tmp.cleanup()

    def test_progress_persists_and_dedupes(self):
        app.record_stage_result(self.doc, "host-1", "a", True, "note")
        app.record_stage_result(self.doc, "host-1", "a", True, "note")
        app.record_stage_result(self.doc, "host-1", "b", False, "")
        entry = app.scenario_progress(self.doc, "host-1")
        self.assertEqual(entry["completed"], ["a"])
        self.assertEqual(entry["attempts"], {"a": 2, "b": 1})
        self.assertEqual(entry["reviews"], {"a": "note"})
        on_disk = json.loads((self.root / "scenarios.json").read_text())
        self.assertIn("demo-001@host-1", on_disk["scenarios"])

    def test_progress_keyed_by_host(self):
        app.record_stage_result(self.doc, "host-1", "a", True, "")
        self.assertEqual(app.scenario_progress(self.doc, "host-2")["completed"], [])

    def test_corrupt_progress_file_is_ignored(self):
        (self.root / "scenarios.json").write_text("{not json")
        self.assertEqual(app.scenario_progress(self.doc, "host-1")["completed"], [])


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


class HecTokenTests(unittest.TestCase):
    def _response(self, entries):
        response = mock.Mock()
        response.status_code = 200
        response.json.return_value = {"entry": entries}
        return response

    def test_prefers_token_that_allows_the_index(self):
        entries = [
            {"content": {"token": "main-only", "disabled": False, "indexes": ["main"]}},
            {"content": {"token": "attack-data", "disabled": False, "indexes": ["attack_data"]}},
        ]
        with mock.patch.object(app, "splunk_request", return_value=self._response(entries)):
            self.assertEqual(app.get_hec_token(), "attack-data")

    def test_rejects_token_without_index_access(self):
        entries = [{"content": {"token": "main-only", "disabled": False, "indexes": ["main"]}}]
        with mock.patch.object(app, "splunk_request", return_value=self._response(entries)):
            with self.assertRaises(app.SplunkError):
                app.get_hec_token()


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


class EnrichmentParsingTests(unittest.TestCase):
    def test_parses_fenced_json_and_drops_unsafe_or_unscoped_hunts(self):
        text = (
            "```json\n"
            '{"description": " Attacker  dumped LSASS.", "hunts": ['
            '{"title": " LSASS access ", "why": "why", "spl": "search index=attack_data EventCode=10"},'
            '{"title": "no index", "spl": "stats count"},'
            '{"title": "unsafe", "spl": "index=attack_data | delete"}'
            "]}\n```"
        )
        parsed = app.parse_enrichment(text)
        self.assertEqual(parsed["description"], "Attacker dumped LSASS.")
        self.assertEqual(len(parsed["hunts"]), 1)
        self.assertEqual(parsed["hunts"][0]["title"], "LSASS access")
        self.assertEqual(parsed["hunts"][0]["spl"], "index=attack_data EventCode=10")

    def test_rejects_reply_without_description(self):
        with self.assertRaises(ValueError):
            app.parse_enrichment('{"hunts": [{"title": "x", "spl": "index=x"}]}')

    def test_recipe_matches_sub_technique_both_ways(self):
        recipe = {"techniques": ["T1003"]}
        self.assertTrue(app.recipe_matches(recipe, ["T1003.001"]))
        self.assertTrue(app.recipe_matches({"techniques": ["T1003.001"]}, ["T1003"]))
        self.assertTrue(app.recipe_matches({"techniques": []}, []))
        self.assertFalse(app.recipe_matches({"techniques": ["T1059"]}, ["T1003"]))


class StudiedStateTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(dir="/tmp/opencode")
        self.root = Path(self._tmp.name)
        self.patches = [
            mock.patch.object(app, "STATE_DIR", self.root),
            mock.patch.object(app, "STUDIED_FILE", self.root / "studied.json"),
        ]
        for patch in self.patches:
            patch.start()
        app._studied_cache.update({"mtime": None, "data": {}})

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self._tmp.cleanup()

    def test_mark_survives_a_cache_reset_and_can_be_cleared(self):
        rel = "attack_techniques/T1003.001/demo"
        app.set_studied(rel, True)
        self.assertTrue(app.get_studied()[rel])
        app._studied_cache.update({"mtime": None, "data": {}})
        self.assertTrue(app.get_studied()[rel])
        app.set_studied(rel, False)
        self.assertNotIn(rel, app.get_studied())


if __name__ == "__main__":
    unittest.main(verbosity=2)
