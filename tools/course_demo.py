"""A five-minute presentation's executable evidence walkthrough; no Java probes.

python3 -m tools.course_demo --out runs/demo-course --verify-manifest
The timed narration is in docs/DEMO_5_PHUT.md; commands do not pretend that a
human presentation or a run on a second machine has occurred.
"""
import argparse
import hashlib
import json
from pathlib import Path

from .catalog import ROOT,verify
from .acceptance import assess
from .observations import require


def walkthrough():
    cve='CVE-2018-1002200'
    case=next(json.loads(s) for s in (ROOT/'data/cases.jsonl').read_text().splitlines() if json.loads(s)['cve_id']==cve)
    versions=[json.loads(s) for s in (ROOT/'data/versions.jsonl').read_text().splitlines()]
    method=next(v for v in versions if v['cve_id']==cve and v['phase']=='after' and not v['is_test'])
    acceptance=assess();require(acceptance==json.loads((ROOT/'data/acceptance-review.json').read_text()),'Stale acceptance JSON')
    entry=next(c for c in acceptance['cases'] if c['cve_id']==cve)
    receipt=ROOT/entry['build_receipt'];raw=json.loads(receipt.read_text())
    pair={s['phase']:s for s in raw['snapshots'] if s['cve_id']==cve}
    require(all(pair[p]['commit']==case[p+'_commit'] for p in pair),'Evidence commit mismatch')
    comparison=json.loads((ROOT/'data/iris-comparison.json').read_text())
    context=[json.loads(s) for s in (ROOT/'data/context-files.jsonl').read_text().splitlines() if s.strip()]
    result=dict(cve_id=cve,advisory=case['advisory_url'],repository=case['repository_url'],
                before_commit=case['before_commit'],after_commit=case['after_commit'],selected_parent_index=case['selected_parent_index'],
                sample_id=method['sample_id'],signature=method['syntactic_signature'],file=method['file_path'],
                lines=[method['start_line'],method['end_line']],code_sha256=method['code_sha256'],method_label=method['label'],
                receipt=entry['build_receipt'],receipt_sha256=hashlib.sha256(receipt.read_bytes()).hexdigest(),
                paired_observations={p:pair[p]['security']['tests'] for p in pair},
                acceptance=acceptance['summary'],comparison_primary=comparison['primary'],comparison_expanded=comparison['expanded'],
                retained_context_references=context,
                review_status=json.loads((ROOT/'data/independent-review-summary.json').read_text())['status'],
                limitations=['Residual sibling-prefix assertion fails after the historical patch; no general SAFE label.',
                             'Path narrowing can omit useful unchanged security context; see GitClientSecurityTest in comparison report.',
                             'No Java CVE probe, new build or human independent review is executed by this walkthrough.'])
    return result


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out',type=Path,required=True);p.add_argument('--verify-manifest',action='store_true')
    a=p.parse_args()
    if a.verify_manifest:verify()
    r=walkthrough();a.out.mkdir(parents=True,exist_ok=False)
    (a.out/'walkthrough.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n')
    print('1. advisory:',r['advisory'])
    print('2. commits:',r['before_commit'],'->',r['after_commit'])
    print('3. method:',r['sample_id'],r['signature'],'lines',r['lines'],'SHA-256',r['code_sha256'])
    print('4. saved behavior:',json.dumps(r['paired_observations']))
    print('5. IRIS comparison:',json.dumps(dict(primary=r['comparison_primary'],expanded=r['comparison_expanded'])))
    print('6. acceptance:',json.dumps(r['acceptance']),'independent review:',r['review_status'])
    print('7. context:',json.dumps(r['retained_context_references']))
