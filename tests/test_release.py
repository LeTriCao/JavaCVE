from collections import defaultdict
import hashlib
import json
import re
import unittest
from unittest.mock import patch
from tools.catalog import ROOT, rows
from tools.catalog import verify_expansion
from tools.security import parse_probe
from tools.review_xstream_followup import SUMMARY


class ReleaseTests(unittest.TestCase):
    def test_readme_local_links_exist(self):
        for target in re.findall(r"\]\(([^)]+)\)",(ROOT/"README.md").read_text(encoding="utf-8")):
            if not target.startswith(("https://","http://","#")):
                self.assertTrue((ROOT/target).exists(),target)

    def test_split_has_no_project_or_exact_token_leakage(self):
        assignments=[json.loads(l) for l in (ROOT/"docs/generated/split-project/assignments.jsonl").read_text().splitlines()]
        hashes,units=defaultdict(set),defaultdict(set)
        for sample in assignments:
            hashes[sample["token_hash"]].add(sample["split"])
            units[sample["unit"]].add(sample["split"])
        self.assertTrue(all(len(s)==1 for s in hashes.values()))
        self.assertTrue(all(len(s)==1 for s in units.values()))
        batch=[json.loads(l) for l in (ROOT/"data/batch-02/versions.jsonl").read_text().splitlines()]
        self.assertEqual({s["sample_id"] for s in assignments},{v["sample_id"] for v in rows("versions")+batch})

    def test_metrics_recompute_from_path_lists(self):
        metrics=json.loads((ROOT/"docs/generated/metrics.json").read_text())
        comparison=metrics["file_comparison"]
        matched=[c for c in comparison["cases"] if c["same_fix"]]
        self.assertEqual(sum(len(c["original_paths"]) for c in matched),comparison["original_java_files"])
        self.assertEqual(sum(len(c["normalized_paths"]) for c in matched),comparison["normalized_java_files"])
        self.assertEqual((len(matched),comparison["original_java_files"],comparison["normalized_java_files"]),(9,60,33))
        self.assertEqual(metrics["current"]["integrity"]["numerator"],187)

    def test_completed_expansion_has_paired_fixture_evidence(self):
        completion=json.loads((ROOT/"data/batch-02/completion.json").read_text())
        self.assertEqual(completion["fully_completed"],len(completion["completed_cves"]))
        for cve in completion["completed_cves"]:
            run_id=completion["evidence_runs"][cve]
            evidence=json.loads((ROOT/"evidence/v0.2.0"/run_id/"run.json").read_text())
            snapshots=[r for r in evidence["snapshots"] if r["cve_id"]==cve]
            self.assertEqual(len(snapshots),2)
            self.assertEqual({r["phase"] for r in snapshots},{"before","after"})
            self.assertTrue(all(r["build_status"]=="PASS" and r["security"]["controls_pass"] for r in snapshots))
            self.assertEqual(len({r["security"]["fixture_sha256"] for r in snapshots}),1)

    def test_inconclusive_security_cannot_be_marked_complete(self):
        original = type(ROOT).read_text
        def corrupted(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path.name == "completion-review.json":
                data = json.loads(text)
                next(c for c in data["cases"] if c["cve_id"] == "CVE-2013-7285")["fully_completed"] = True
                return json.dumps(data)
            return text
        with patch.object(type(ROOT), "read_text", corrupted):
            with self.assertRaisesRegex(ValueError, "Completion contradicts"):
                verify_expansion()

    def test_completed_cve_cannot_borrow_another_cve_receipt(self):
        original = type(ROOT).read_text
        def corrupted(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path.name == "completion.json":
                data = json.loads(text)
                data["evidence_runs"]["CVE-2016-9177"] = data["evidence_runs"]["CVE-2022-4244"]
                return json.dumps(data)
            return text
        with patch.object(type(ROOT), "read_text", corrupted):
            with self.assertRaisesRegex(ValueError, "lacks its own paired receipt"):
                verify_expansion()

    def test_assessment_observations_match_immutable_logs(self):
        review=json.loads((ROOT/"data/batch-02/completion-review.json").read_text())
        for run_id, expected in review["receipt_sha256"].items():
            self.assertEqual(hashlib.sha256((ROOT/"evidence/v0.2.0"/run_id/"run.json").read_bytes()).hexdigest(),expected)
        for case in review["cases"]:
            kind="spark-local" if case["cve_id"]=="CVE-2016-9177" else "xstream-local"
            for observed in case["observations"]:
                log=ROOT/observed["log"]
                self.assertEqual(hashlib.sha256(log.read_bytes()).hexdigest(),observed["log_sha256"])
                self.assertEqual(parse_probe(kind,log.read_text(encoding="utf-8")),observed["tests"])

    def test_current_batch_statistics_agree(self):
        completion=json.loads((ROOT/"data/batch-02/completion.json").read_text())
        status=json.loads((ROOT/"data/batch-02/build-status.json").read_text())
        metrics=json.loads((ROOT/"docs/generated/metrics.json").read_text())
        self.assertEqual(metrics["catalog"]["expansion"],verify_expansion())
        self.assertEqual({c["cve_id"] for c in status["cases"] if c["fully_completed"]},set(completion["completed_cves"]))
        self.assertEqual(status["source_built_snapshots"],sum(r.get("build_status")=="PASS" for c in status["cases"] for r in (c["before"],c["after"])))

    def test_xstream_upstream_counts_are_not_paired_security(self):
        review=json.loads((ROOT/"data/batch-02/completion-review.json").read_text())
        versions=[json.loads(l) for l in (ROOT/"data/batch-02/versions.jsonl").read_text().splitlines()]
        expected={"CVE-2020-26217":[7,9],"CVE-2021-21345":[11,13]}
        for cve, counts in expected.items():
            case=next(c for c in review["cases"] if c["cve_id"]==cve)
            self.assertFalse(case["fully_completed"])
            self.assertIsNone(case["behavior_run_id"])
            self.assertEqual([o["tests"] for o in case["upstream_observations"]],counts)
            for observed in case["upstream_observations"]:
                log=ROOT/observed["log"]
                self.assertEqual(hashlib.sha256(log.read_bytes()).hexdigest(),observed["log_sha256"])
                self.assertEqual(list(map(int,SUMMARY.findall(log.read_text(encoding="utf-8"))[-1])),[observed["tests"],0,0,0])
            self.assertEqual({c["id"] for c in case["criteria"] if c["status"]=="NOT_MET"},{"ordinary_controls","paired_security_behavior"})
            self.assertEqual({v["label"] for v in versions if v["cve_id"]==cve},{"UNCONFIRMED"})

    def test_upstream_only_cve_cannot_be_promoted(self):
        original = type(ROOT).read_text
        for cve in ("CVE-2020-26217", "CVE-2021-21345"):
            def corrupted(path, *args, **kwargs):
                text = original(path, *args, **kwargs)
                if path.name == "completion-review.json":
                    data = json.loads(text)
                    next(c for c in data["cases"] if c["cve_id"] == cve)["fully_completed"] = True
                    return json.dumps(data)
                return text
            with self.subTest(cve=cve), patch.object(type(ROOT), "read_text", corrupted):
                with self.assertRaisesRegex(ValueError, "Completion contradicts"):
                    verify_expansion()

    def test_diagnosis_preserves_uncertainty_and_dependency_inventory(self):
        diagnosis=json.loads((ROOT/"data/batch-02/xstream-diagnosis.json").read_text())
        receipt=json.loads((ROOT/diagnosis["source_receipt"]).read_text())
        self.assertEqual(hashlib.sha256((ROOT/diagnosis["source_receipt"]).read_bytes()).hexdigest(),diagnosis["source_receipt_sha256"])
        pair=[r for r in receipt["snapshots"] if r["cve_id"]=="CVE-2013-7285"]
        self.assertEqual(pair[0]["dependencies"],pair[1]["dependencies"])
        self.assertEqual([{k:d[k] for k in ("path","sha256")} for d in diagnosis["dependencies"]],pair[0]["dependencies"])
        self.assertEqual(diagnosis["root_cause_status"],"UNDETERMINED_FROM_EXISTING_LOGS")
        self.assertEqual(diagnosis["exception_phase"],"UNCONFIRMED")
        for log in diagnosis["logs"].values():
            path=ROOT/log["path"]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),log["sha256"])
            text=path.read_text(encoding="utf-8")
            self.assertIn("OBSERVED_EXCEPTION=com.thoughtworks.xstream.converters.ConversionException",text)
            self.assertNotIn("Caused by:",text)
        self.assertTrue(all(s["identical"] and s["before_sha256"]==s["after_sha256"] for s in diagnosis["unchanged_sources"]))

    def test_public_receipts_are_redacted(self):
        for path in (ROOT/"evidence/v0.2.0").rglob("*"):
            if path.is_file() and path.suffix in (".json",".log"):
                text=path.read_text(encoding="utf-8")
                self.assertNotIn("/mnt/d/",text,str(path))
                self.assertNotIn(str(ROOT),text,str(path))
                self.assertIsNone(re.search(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b",text),str(path))
