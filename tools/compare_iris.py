"""Offline, same-fix IRIS seed vs selected-parent comparison from pinned Git objects.

python3 -m tools.compare_iris --out runs/iris-comparison-new
No network, source builds or security probes; missing snapshots are exclusions.
"""
import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from .catalog import ROOT
from .observations import require

RULE = 'Unique case-sensitive .java paths per CVE; git diff --name-only --no-renames -z START FIX -- *.java; includes tests/resources; sum CVE-path counts across cases, not globally unique paths.'


def path_delta(original, normalized):
    a,b=set(original),set(normalized)
    return dict(removed_paths=sorted(a-b),added_paths=sorted(b-a),retained_paths=sorted(a&b))


def summarize(records):
    eligible=[r for r in records if r['eligible']]
    a=sum(r['original_count'] for r in eligible);b=sum(r['normalized_count'] for r in eligible)
    return dict(cves=len(eligible),original_paths=a,normalized_paths=b,net_reduction=a-b,
                reduction_percent=round(100*(a-b)/a,6) if a else None,
                removed_paths=sum(len(r['removed_paths']) for r in eligible),
                added_paths=sum(len(r['added_paths']) for r in eligible),
                iris_annotated_java_paths=sum(len(r['iris_annotated_paths']) for r in eligible),
                missing_iris_annotated_paths=sum(len(r['missing_iris_annotated_paths']) for r in eligible),
                context_references=sum(len(r['context_files']) for r in eligible))


def compare(pilot_repos=None,batch_repos=None,fallback_repos=None,raw_out=None):
    pilot_repos=pilot_repos or ROOT/'.cache/measurement-repos'
    batch_repos=batch_repos or ROOT/'.cache/batch02-repos'
    fallback_repos=fallback_repos or ROOT/'.cache/repos'
    env=dict(os.environ,GIT_NO_LAZY_FETCH='1',GIT_ALLOW_PROTOCOL='file')
    source=ROOT/'evidence/inputs'
    with (source/'project_info.csv').open(newline='') as f: projects=list(csv.DictReader(f))
    with (source/'fix_info.csv').open(newline='') as f: annotations=list(csv.DictReader(f))
    records=[]
    for batch,folder,repos in [('pilot',ROOT/'data',pilot_repos),('batch02',ROOT/'data/batch-02',batch_repos)]:
        cases=[json.loads(s) for s in (folder/'cases.jsonl').read_text().splitlines()]
        indexed=[json.loads(s) for s in (folder/'files.jsonl').read_text().splitlines()]
        for case in cases:
            cve=case['cve_id'];seed=case['seed_commit'];parent=case['before_commit'];fix=case['after_commit']
            metadata=[p for p in projects if p['cve_id']==cve and p['buggy_commit_id']==seed]
            require(len(metadata)==1,'Ambiguous/missing raw IRIS identity: '+cve)
            meta=metadata[0];fix_refs=[v.strip() for v in meta['fix_commit_ids'].split(';') if v.strip()]
            require(fix_refs==case['seed_fix_commits'],'Raw IRIS fix references differ: '+cve)
            row=dict(cve_id=cve,batch=batch,project=case['project'],project_slug=meta['project_slug'],
                     repository_url=case['repository_url'],provenance=case['provenance'],
                     iris_before_commit=seed,javacve_before_commit=parent,common_fix_commit=fix,
                     iris_fix_references=fix_refs,selected_parent_index=case['selected_parent_index'],
                     eligible=False,exclusion_reason=None,original_count=None,normalized_count=None)
            if fix_refs!=[fix]:
                row['exclusion_reason']='MULTIPLE_IRIS_FIXES' if len(fix_refs)>1 else 'FIX_MAPPING_CHANGED'
                records.append(row);continue
            candidates=[repos/cve,fallback_repos/cve]
            repo=next((p for p in candidates if p.is_dir() and all(subprocess.run(
                ['git','-C',str(p),'cat-file','-e',sha+'^{commit}'],env=env,capture_output=True).returncode==0
                for sha in (seed,parent,fix))),None)
            if repo is None:
                row['exclusion_reason']='MISSING_PINNED_LOCAL_SEED_OR_SNAPSHOT'
                records.append(row);continue
            def git(*args):return subprocess.check_output(['git','-C',str(repo),*args],env=env)
            parents=[x[7:].decode() for x in git('cat-file','-p',fix).splitlines() if x.startswith(b'parent ')]
            require(parents[case['selected_parent_index']]==parent,'Selected parent mismatch: '+cve)
            def paths(start):
                return sorted({p.decode() for p in git('diff','--name-only','--no-renames','-z',start,fix,'--','*.java').split(b'\0') if p})
            old,new=paths(seed),paths(parent)
            expected=sorted({f['file_path_after'] or f['file_path_before'] for f in indexed if f['cve_id']==cve})
            require(new==expected,'Normalized paths differ from source index: '+cve)
            annotated=sorted({r['file'] for r in annotations if r['project_slug']==meta['project_slug'] and r['commit']==fix and r['file'].endswith('.java')})
            delta=path_delta(old,new)
            title=git('show','-s','--format=%B',fix).decode(errors='replace')
            issue_ids=sorted(set(re.findall(r'SECURITY-\d+|CVE-\d{4}-\d+',title)))
            path_review=[];context=[]
            for path in sorted(set(old)|set(new)):
                def blob(commit):
                    info=git('ls-tree','-z',commit,'--',path)
                    if not info:return None,None
                    identity=info.split(b'\t',1)[0].split()[-1].decode()
                    data=git('cat-file','blob',identity)
                    return identity,hashlib.sha256(data).hexdigest()
                identities={}
                for name,sha in [('iris_before',seed),('javacve_before',parent),('fix',fix)]:
                    oid,h=blob(sha);identities[name]=dict(git_blob=oid,sha256=h)
                classification='retained' if path in old and path in new else 'removed_from_changed_set' if path in old else 'new_in_parent_diff'
                item=dict(path=path,classification=classification,iris_fix_annotation=path in annotated,identities=identities)
                if classification=='removed_from_changed_set':
                    require(identities['javacve_before']==identities['fix'],'Removed path unexpectedly differs in fix: '+path)
                    if identities['javacve_before']['git_blob']:
                        content=git('cat-file','blob',identities['javacve_before']['git_blob']).decode(errors='replace')
                        matching=[issue for issue in issue_ids if issue in content]
                        if matching:
                            context.append(dict(cve_id=cve,path=path,reason='Removed changed-path file contains the same issue ID as the fix message; retain as security context, not automatically irrelevant.',
                                                matching_issue_ids=matching,before_commit=parent,after_commit=fix,
                                                before_blob=identities['javacve_before']['git_blob'],after_blob=identities['fix']['git_blob'],
                                                code_sha256=identities['fix']['sha256'],
                                                source_url=case['repository_url']+'/blob/'+fix+'/'+path,
                                                changed_callable_sample=False))
                path_review.append(item)
            patch=git('diff','--no-renames',parent,fix,'--','*.java')
            intervening=git('diff','--no-renames',seed,parent,'--','*.java')
            if raw_out:
                (raw_out/(cve+'-parent-to-fix.patch')).write_bytes(patch)
                (raw_out/(cve+'-seed-to-parent.patch')).write_bytes(intervening)
            row.update(eligible=True,original_paths=old,normalized_paths=new,original_count=len(old),normalized_count=len(new),
                       **delta,iris_annotated_paths=annotated,missing_iris_annotated_paths=sorted(set(annotated)-set(new)),
                       context_files=context,path_review=path_review,patch_sha256=hashlib.sha256(patch).hexdigest(),
                       intervening_diff_sha256=hashlib.sha256(intervening).hexdigest(),fix_message=title,
                       direct_fix_java_paths_retained=(new==expected),
                       snapshot_trees={name:git('rev-parse',sha+'^{tree}').decode().strip() for name,sha in [('iris_before',seed),('javacve_before',parent),('fix',fix)]})
            records.append(row)
    primary=summarize([r for r in records if r['batch']=='pilot'])
    expanded=summarize(records)
    return dict(schema='iris-parent-comparison-v1',date_local='2026-11-25',benchmark_revision='d2059f299a80a68ea4a0b0315eec2f42b8743776',
                rule=RULE,network_used=False,source_inputs_sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [source/'project_info.csv',source/'fix_info.csv']},
                primary=primary,expanded=expanded,prior_60_to_33_matches=(primary['cves'],primary['original_paths'],primary['normalized_paths'])==(9,60,33),
                limitations=['Path count is not security-label precision, source lines, processing time, build improvement or model accuracy.',
                             'Parent-diff equality retains the chosen patch paths by construction; independent check uses raw IRIS fix_info.csv annotations.',
                             'Some removed paths can be security context; context references are separate from the 409 changed-callable versions.',
                             'Missing seed objects are reported as exclusions; no network fetch is attempted.'],cases=records)


def write_outputs(result,out):
    out.mkdir(parents=True,exist_ok=False)
    (out/'comparison.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    with (out/'comparison.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['cve_id','batch','eligible','exclusion_reason','iris_before_commit','javacve_before_commit','common_fix_commit','original_count','normalized_count']
        w=csv.DictWriter(f,fieldnames=fields,extrasaction='ignore');w.writeheader();w.writerows(result['cases'])
    with (out/'paths.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.writer(f);w.writerow(['cve_id','path','classification','iris_fix_annotation'])
        for r in result['cases']:
            for p in r.get('path_review',[]):w.writerow([r['cve_id'],p['path'],p['classification'],p['iris_fix_annotation']])


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--out',type=Path,required=True)
    p.add_argument('--pilot-repos',type=Path)
    p.add_argument('--batch-repos',type=Path)
    p.add_argument('--fallback-repos',type=Path)
    p.add_argument('--raw-diffs',type=Path,help='Optional local-only directory for raw third-party patches')
    args=p.parse_args()
    if args.raw_diffs:args.raw_diffs.mkdir(parents=True,exist_ok=False)
    result=compare(args.pilot_repos,args.batch_repos,args.fallback_repos,args.raw_diffs)
    write_outputs(result,args.out)
    print(json.dumps(dict(primary=result['primary'],expanded=result['expanded'],prior_60_to_33_matches=result['prior_60_to_33_matches'])))
