"""Regression checks for the shared evidence policy; no Java execution."""
import copy
import json
import unittest

from tools.acceptance import ROOT, PILOT_RUN, paired_behavior, local_ordinary_controls, ordinary_api_pair, assess
from tools.ordinary_replay import parse_controls


class AcceptanceTests(unittest.TestCase):
    def pair(self, rid=PILOT_RUN, cve="CVE-2017-1000487"):
        run = json.loads((ROOT / "evidence/v0.2.0" / rid / "run.json").read_text())
        return {s["phase"]: s for s in run["snapshots"] if s["cve_id"] == cve}

    def test_partial_fix_can_complete_with_residual_failure(self):
        pair = self.pair(cve="CVE-2018-1002200")
        controls, behavior, improved = paired_behavior(pair)
        self.assertTrue(controls and behavior)
        self.assertEqual(improved, ["parent_containment"])
        self.assertFalse(pair["after"]["security"]["all_security_assertions_pass"])

    def test_inconclusive_pass_pass_is_not_behavior_evidence(self):
        pair = self.pair("4063ba008c3644f5ad4d015ccd4cbcc4", "CVE-2013-7285")
        controls, behavior, improved = paired_behavior(pair)
        self.assertTrue(controls)
        self.assertFalse(behavior)
        self.assertEqual(improved, [])

    def test_missing_control_or_changed_fixture_blocks_acceptance(self):
        for mutation in ("missing_control", "changed_fixture", "duplicate_assertion"):
            with self.subTest(mutation=mutation):
                pair = copy.deepcopy(self.pair())
                sec = pair["after"]["security"]
                if mutation == "missing_control":
                    sec["tests"] = [t for t in sec["tests"] if t["role"] != "control"]
                elif mutation == "changed_fixture":
                    sec["fixture_sha256"] = "0" * 64
                else:
                    sec["tests"].append(copy.deepcopy(sec["tests"][0]))
                self.assertFalse(paired_behavior(pair)[1])

    def test_all_cases_use_same_gates_and_saved_assessment_matches(self):
        result = assess()
        self.assertEqual(result, json.loads((ROOT / "data/acceptance-review.json").read_text()))
        self.assertEqual(len({c["cve_id"] for c in result["cases"]}), 20)
        for case in result["cases"]:
            self.assertEqual(set(case["criteria"]), set(result["criteria"]))
            self.assertEqual(case["accepted_common"], all(v == "MET" for v in case["criteria"].values()))
        self.assertFalse(result["proposed_target"]["instructor_confirmed"])

    def test_separate_control_must_match_both_pinned_snapshots(self):
        case = next(json.loads(s) for s in (ROOT / "data/batch-02/cases.jsonl").read_text().splitlines()
                    if json.loads(s)["cve_id"] == "CVE-2023-37460")
        record = json.loads((ROOT / "evidence/plexus-control/run.json").read_text())
        self.assertTrue(local_ordinary_controls(case, record))
        changed = copy.deepcopy(record)
        changed["snapshots"][1]["commit"] = "0" * 40
        self.assertFalse(local_ordinary_controls(case, changed))

    def test_ordinary_replay_cannot_borrow_commits_or_artifacts(self):
        case = dict(cve_id="CVE-TEST", before_commit="a" * 40, after_commit="b" * 40)
        artifacts = {p: dict(artifact_sha256=h*64) for p,h in [('before','c'),('after','d')]}
        pair = [dict(cve_id="CVE-TEST", phase=p, commit=case[p+"_commit"], status="PASS", exit_code=0,
                     artifact_sha256=artifacts[p]['artifact_sha256'], fixture_sha256='e'*64,
                     build_status='REUSED_VERIFIED', source_built_in_this_run=False,
                     controls=[dict(name=n,**{'pass':True}) for n in ['string_roundtrip','empty_string_roundtrip','integer_roundtrip']])
                for p in ("before", "after")]
        self.assertTrue(ordinary_api_pair(case, pair, artifacts))
        changed = copy.deepcopy(pair)
        changed[1]["commit"] = "d" * 40
        self.assertFalse(ordinary_api_pair(case, changed, artifacts))
        changed = copy.deepcopy(pair)
        changed[1]["artifact_sha256"] = "f" * 64
        self.assertFalse(ordinary_api_pair(case, changed, artifacts))
        self.assertFalse(ordinary_api_pair(case, pair + [pair[0]], artifacts))

    def test_ordinary_replay_rejects_missing_or_duplicate_observations(self):
        with self.assertRaisesRegex(ValueError, 'Missing/duplicate'):
            parse_controls('CONTROL|string_roundtrip|true\n')
        with self.assertRaisesRegex(ValueError, 'Missing/duplicate'):
            parse_controls('CONTROL|string_roundtrip|true\n' * 3)


if __name__ == "__main__":
    unittest.main()
