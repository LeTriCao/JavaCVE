from collections import defaultdict
import json
import re
import unittest
from tools.catalog import ROOT, rows


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
        evidence=json.loads((ROOT/"evidence/v0.2.0"/completion["evidence_run_id"]/"run.json").read_text())
        for cve in completion["completed_cves"]:
            snapshots=[r for r in evidence["snapshots"] if r["cve_id"]==cve]
            self.assertEqual({r["phase"] for r in snapshots},{"before","after"})
            self.assertTrue(all(r["build_status"]=="PASS" and r["security"]["controls_pass"] for r in snapshots))

    def test_public_receipts_are_redacted(self):
        for path in (ROOT/"evidence/v0.2.0").rglob("*"):
            if path.is_file() and path.suffix in (".json",".log"):
                text=path.read_text(encoding="utf-8")
                self.assertNotIn("/mnt/d/",text,str(path))
                self.assertNotIn(str(ROOT),text,str(path))
                self.assertIsNone(re.search(r"\b(?:ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b",text),str(path))
