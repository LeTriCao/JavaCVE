"""Validate independently filled forms against a coordinator-only baseline.

No dataset labels are changed. Blank/unfinished forms stay PENDING, with no
agreement percentage. AI agreement is not accuracy against a human gold set.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
from datetime import date

LABELS={'VULNERABLE','RESOLVED_TARGET','UNCONFIRMED'}


def analyze(reference,paths):
    refs={r['review_id']:r for r in reference['samples']}
    candidates={};issues=[];scanned=[];seen_files=set();blank=0
    for path in paths:
        content=path.read_bytes();hashed=hashlib.sha256(content).hexdigest()
        scanned.append(dict(path=path.as_posix(),sha256=hashed,duplicate_content=hashed in seen_files))
        if hashed in seen_files:continue
        seen_files.add(hashed)
        for row in csv.DictReader(content.decode('utf-8-sig').splitlines()):
            rid=row.get('review_id','')
            if not row.get('reviewer_decision','').strip():blank+=1;continue
            reason=None;r=refs.get(rid)
            if r is None or row.get('sample_id')!=r['sample_id']:reason='UNKNOWN_REVIEW_OR_SAMPLE_ID'
            elif r.get('source_url') and row.get('source_url')!=r['source_url']:reason='SOURCE_REFERENCE_CHANGED'
            elif r.get(row.get('phase','')+'_commit') and row.get('commit')!=r[row['phase']+'_commit']:reason='SOURCE_COMMIT_CHANGED'
            elif row.get('reviewer_decision') not in LABELS:reason='INVALID_DECISION'
            elif not all(row.get(k,'').strip() for k in ['reviewer_name','review_date','reason','evidence_checked']):reason='INCOMPLETE_REVIEW_METADATA'
            elif row['reviewer_name'].strip().lower() in {'ai','codex','chatgpt','assistant'}:reason='NOT_INDEPENDENT_HUMAN'
            elif row.get('review_status','').upper()!='COMPLETED':reason='REVIEW_NOT_MARKED_COMPLETED'
            else:
                try:date.fromisoformat(row['review_date'])
                except ValueError:reason='INVALID_REVIEW_DATE'
            if reason:issues.append(dict(review_id=rid,reason=reason));continue
            key=(row['reviewer_name'].strip(),row['review_date'],row['reviewer_decision'],row['reason'],row['evidence_checked'])
            candidates.setdefault(rid,{})[key]=row
    valid=[]
    for rid,entries in candidates.items():
        if len(entries)!=1:issues.append(dict(review_id=rid,reason='CONFLICTING_COMPLETED_FORMS'));continue
        row=next(iter(entries.values()));baseline=refs[rid]['baseline_ai_label']
        valid.append(dict(review_id=rid,sample_id=row['sample_id'],reviewer=row['reviewer_name'],
                          ai_baseline=baseline,human_decision=row['reviewer_decision'],agrees=baseline==row['reviewer_decision'],
                          reason=row['reason'],evidence_checked=row['evidence_checked']))
    matches=sum(r['agrees'] for r in valid)
    return dict(status='PENDING' if not valid else 'COMPLETED' if len(valid)==len(refs) else 'PARTIAL',
                expected_samples=len(refs),valid_samples=len(valid),pending_samples=len(refs)-len(valid),
                matches=matches,agreement_rate=matches/len(valid) if valid else None,
                disagreement_count=len(valid)-matches,disagreements=[r for r in valid if not r['agrees']],
                valid_reviews=valid,issues=issues,scanned_files=scanned,unique_file_contents=len(seen_files),blank_rows=blank,
                caveat='Agreement with an AI baseline on purposively selected samples; not dataset accuracy. No label changes are applied.')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--reference',type=Path,required=True)
    p.add_argument('--forms',type=Path,action='append',required=True)
    p.add_argument('--out',type=Path,required=True)
    a=p.parse_args();result=analyze(json.loads(a.reference.read_text()),a.forms)
    with a.out.open('x',encoding='utf-8') as f:f.write(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps({k:result[k] for k in ['status','valid_samples','pending_samples','agreement_rate','disagreement_count']}))
