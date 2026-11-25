"""Replay harmless API controls using hash-verified, previously source-built JARs."""
import json
import os
import sys
import tempfile

from .build import ROOT, digest, tool_paths
from .observations import require
from .runtime import Run, StepError

TARGETS = ("CVE-2013-7285", "CVE-2020-26217", "CVE-2021-21345")
NAMES = {"string_roundtrip", "empty_string_roundtrip", "integer_roundtrip"}


def parse_controls(output):
    controls = []
    for line in output.splitlines():
        if line.startswith("CONTROL|"):
            parts = line.split("|")
            require(len(parts) == 3 and parts[1] in NAMES and parts[2] in ("true", "false"), "Malformed ordinary control")
            controls.append(dict(name=parts[1], **{"pass": parts[2] == "true"}))
    require(len(controls) == len(NAMES) and {c["name"] for c in controls} == NAMES, "Missing/duplicate ordinary controls")
    return controls


def main():
    cases = [json.loads(l) for l in (ROOT / 'data/batch-02/cases.jsonl').read_text().splitlines()]
    ledger = {c['cve_id']: c for c in json.loads((ROOT / 'data/batch-02/build-status.json').read_text())['cases']}
    fixture = ROOT / 'fixtures/OrdinaryXStreamProbe.java'
    run = Run('ordinary-api-replay', 'String/empty String/Integer roundtrip; DomDriver; no security probes')
    run.report.update(scope='Functional API controls only. Reused hash-verified source-built JARs; no new builds or CVE behavior claims.',
                      fixture_sha256=digest(fixture))
    tools = tool_paths(ROOT.parent / 'JavaCVE_Reproducible')
    env = os.environ.copy()
    env['JAVA_HOME'] = str(tools['jdk'])
    env['PATH'] = str(tools['jdk'] / 'bin') + os.pathsep + env['PATH']
    run.report['toolchain'] = {'java': run.execute('java-version', [tools['jdk'] / 'bin/java', '-version'], env=env)}
    for case in cases:
        if case['cve_id'] not in TARGETS:
            continue
        item = ledger[case['cve_id']]
        raw_path = ROOT / 'runs' / item['build_run_id'] / 'run.json'
        if not raw_path.is_file():
            run.finish(StepError('Raw source-build artifacts are unavailable; rebuild the pinned snapshots before replay',
                                 127, 'MISSING_DEPENDENCY'))
            return run.directory
        raw = json.loads(raw_path.read_text())
        for phase in ('before', 'after'):
            original = next(s for s in raw['snapshots'] if s['cve_id'] == case['cve_id'] and s['phase'] == phase)
            record = dict(cve_id=case['cve_id'], phase=phase, commit=case[phase + '_commit'], status='running',
                          fixture_sha256=digest(fixture), build_status='REUSED_VERIFIED', source_built_in_this_run=False,
                          source_receipt=f"evidence/v0.2.0/{item['build_run_id']}/run.json",
                          artifact_sha256=original['artifact_sha256'], driver='DomDriver', policy='Pinned default; no allowTypes or policy overrides')
            run.report['snapshots'].append(record)
            try:
                require(original['commit'] == record['commit'] and original.get('build_status') == 'PASS', 'Original source build identity differs')
                artifact = (raw_path.parent / original['artifact']).resolve()
                require(artifact.is_relative_to(raw_path.parent.resolve()) and digest(artifact) == item[phase]['artifact_sha256'] == original['artifact_sha256'], 'Original artifact hash differs')
                with tempfile.TemporaryDirectory(prefix='javacve-ordinary-api-') as tmp:
                    owner = (case['cve_id'], phase, record['commit'])
                    run.execute('ordinary-compile', [tools['jdk'] / 'bin/javac', '-encoding', 'UTF-8', '-cp', artifact, '-d', tmp, fixture], env=env, owner=owner)
                    output = run.execute('ordinary-tests', [tools['jdk'] / 'bin/java', '-cp', os.pathsep.join((tmp, str(artifact))), 'OrdinaryXStreamProbe'], env=env, owner=owner)
                    controls = parse_controls(output)
                    require(all(c['pass'] for c in controls), 'Ordinary control failed')
                    record.update(status='PASS', exit_code=0, controls=controls)
            except Exception as exc:
                record.update(status='FAIL', exit_code=getattr(exc,'code',1), error=str(exc), error_category=getattr(exc,'category','VALIDATION'))
            run.save()
            print(case['cve_id'], phase, record['status'], record.get('error',''), flush=True)
    run.finish(None if all(s['status'] == 'PASS' for s in run.report['snapshots']) else StepError('Ordinary API controls incomplete'))
    return run.directory


if __name__ == '__main__':
    directory = main()
    sys.exit(0 if json.loads((directory / 'run.json').read_text())['status'] == 'PASS' else 1)
