"""Apply the scoped AI review of the new Expand fixture to a separate batch.

Never promote other callables merely because their fix commit exists.
"""
import argparse
from collections import Counter
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tools.observations import require
from tools.runtime import read_run, utc
from tools.quality import write_json


def review(folder,evidence):
    _,run = read_run(evidence)
    selected = [r for r in run["snapshots"] if r["cve_id"] == "CVE-2022-4244"]
    require(len(selected)==2 and {r["phase"] for r in selected}=={"before","after"},"Expected one source-built pair")
    for r in selected:
        require(r["status"]=="PASS" and r["build_status"]=="PASS","Build/fixture not verified")
        require(r["security"]["controls_pass"] and not r["security"]["all_security_assertions_pass"],"Expected residual boundary failure")
        values = {t["name"]:t["pass"] for t in r["security"]["tests"]}
        require(values["sibling_prefix_containment"] is False,"Residual boundary observation differs")
        require(values["parent_containment"] == (r["phase"]=="after"),"Primary before-after behavior differs")
    versions = [json.loads(l) for l in (folder/"versions.jsonl").read_text(encoding="utf-8").splitlines()]
    decisions = []
    for v in versions:
        if v["cve_id"] != "CVE-2022-4244":
            continue
        require(v["syntactic_signature"].startswith("Expand#extractFile("),"Unexpected method in scoped review")
        previous = v["label"]
        v.update(label="VULNERABLE",rule_id="B02_EXPAND_BOUNDARY",unknown_reason_group=None,
                 label_scope="Caller passes an untrusted ZIP to Expand with a writable destination. Before writes parent traversal; after blocks the primary parent input but still writes outside for a sibling directory sharing the output prefix. Applies to the pinned historical snapshots and tested API.",
                 evidence_needed="Independent human review remains pending; no universal safety claim.",evidence_run_id=run["run_id"])
        decisions.append(dict(sample_id=v["sample_id"],commit=v["commit"],previous_label=previous,decision="VULNERABLE",
                              reviewer="AI",independent_human_review=False,review_utc=utc(),scope=v["label_scope"],
                              evidence_run_id=run["run_id"],fixture_sha256=selected[0]["security"]["fixture_sha256"],
                              source_lines=[v["start_line"],v["end_line"]],reason="Absolute-path string prefix guard lacks a directory boundary; bounded paired probe corroborates the residual failure."))
    require(len(decisions)==2,"Expected two reviewed Expand method versions")
    (folder/"versions.jsonl").write_text("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in versions),encoding="utf-8")
    cases = [json.loads(l) for l in (folder/"cases.jsonl").read_text(encoding="utf-8").splitlines()]
    for c in cases:
        if c["cve_id"]=="CVE-2022-4244":
            c.update(after_label="VULNERABLE",check="plexus-expand",label_scope=decisions[0]["scope"],evidence_sets=["batch02_source_build_security"],evidence_run_id=run["run_id"])
    (folder/"cases.jsonl").write_text("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in cases),encoding="utf-8")
    with (folder/"reviews.jsonl").open("x",encoding="utf-8") as stream:
        stream.write("".join(json.dumps(r,ensure_ascii=False)+"\n" for r in decisions))
    write_json(folder/"completion.json",dict(selected=10,source_normalized=10,fully_completed=1,
               completed_cves=["CVE-2022-4244"],labels=dict(Counter(v["label"] for v in versions)),
               definition="Source identity, extraction, scoped AI method review, paired source builds, controls and paired security behavior; independent human review is separately pending.",
               reviewer="AI",independent_human_reviews=0,evidence_run_id=run["run_id"]))
    print("Reviewed two method versions; batch completion 1/10")


if __name__=="__main__":
    p=argparse.ArgumentParser()
    p.add_argument("folder",type=Path)
    p.add_argument("evidence",type=Path)
    a=p.parse_args()
    review(a.folder,a.evidence)
