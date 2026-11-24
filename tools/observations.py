"""Read submitted JSON and Surefire XML as data, without extracting or executing an archive."""
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET
from zipfile import ZipFile


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_archive(path, cases):
    with ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), "Duplicate ZIP names")

        def rows(filename):
            return json.loads(archive.read("results/" + filename + ".json"))

        def index(values):
            out = {(x["cve_id"], x["phase"]): x for x in values}
            require(len(out) == len(values), "Duplicate case/phase")
            return out

        build = index(rows("build_summary"))
        checks = index(rows("regression_summary"))
        replay = index(rows("replay_summary"))
        upstream = index(rows("upstream_summary"))
        integrity = index(rows("source_integrity"))
        expected = {(c["cve_id"], p) for c in cases if "wsl" in c["evidence_sets"] for p in ("before", "after")}
        require(expected == build.keys() == checks.keys() == replay.keys() == integrity.keys(), "Case coverage mismatch")
        require(upstream.keys() <= expected, "Unknown upstream case")
        result = []
        for c in cases:
            for phase in ("before", "after"):
                key = c["cve_id"], phase
                if key not in expected:
                    continue
                b, r, again, i = build[key], checks[key], replay[key], integrity[key]
                commit = c[phase + "_commit"]
                require(b["commit"] == r["commit"] == again["commit"] == commit, "Commit mismatch")
                require(b["artifact_sha256"] == r["artifact_sha256"] == again["artifact_sha256"], "JAR mismatch")
                require(r["status"] == again["status"] == "EXECUTED" and r["process_exit_code"] == again["process_exit_code"] == 0, "Incomplete check run")
                require(r["fixture_sha256"] == again["fixture_sha256"], "Check definitions differ")
                require(b["build_exit_code"] == b["classpath_exit_code"] == 0, "Historical build incomplete")
                require(i["pass"] and i["archive_sha256_matches"] and not i["changed_files"], "Historical source verification failed")
                by_phase = "results/{}/{}/".format(*key)
                require(b == json.loads(archive.read(by_phase + "build.json")), "Build detail mismatch")
                def outcomes(row):
                    data = {(t["name"], t["role"]): t["pass"] for t in row["tests"]}
                    require(len(data) == len(row["tests"]) and all(type(v) is bool for v in data.values()), "Invalid check list")
                    return data
                tests = outcomes(r)
                require(tests == outcomes(again) and bool(tests), "Historical replay mismatch")
                scored = {}
                for role in ("control", "security"):
                    values = [v for (_, k), v in tests.items() if k == role]
                    scored[role] = {"pass": sum(values), "fail": len(values) - sum(values)}
                require(sum(x["pass"] + x["fail"] for x in scored.values()) == len(tests), "Unknown test role")
                suite_totals = {k: 0 for k in ("tests", "failures", "errors", "skipped")}
                if key in upstream:
                    u = upstream[key]
                    require(u["exit_code"] == 0, "Upstream exit")
                    xml_reports = {}
                    for name in names:
                        if name.startswith(by_phase + "surefire/TEST-") and name.endswith(".xml"):
                            attrs = ET.fromstring(archive.read(name)).attrib
                            require(attrs["name"] not in xml_reports, "Duplicate XML suite")
                            xml_reports[attrs["name"]] = {k: int(attrs[k]) for k in suite_totals}
                    reports = {s["suite"]: {k: s[k] for k in suite_totals} for s in u["reports"]}
                    require(reports == xml_reports and bool(reports), "Surefire mismatch")
                    for s in reports.values():
                        for k in suite_totals:
                            suite_totals[k] += s[k]
                result.append({"cve_id": key[0], "phase": phase, "commit": commit,
                               "jar_sha256_reported": b["artifact_sha256"], "build_exit": b["build_exit_code"],
                               "file_states_reported": i["archived_files_checked"], "checks": scored,
                               "upstream": suite_totals, "upstream_measured": key in upstream})
    return {"archive_sha256": hashlib.sha256(Path(path).read_bytes()).hexdigest(), "observations":result}
