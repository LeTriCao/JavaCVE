"""Reparse indexed source and verify callable node boundaries and names."""
import json
from .batch import parser
from .catalog import rows
from .pipeline import git
from .observations import require


def audit(repos,batch=None):
    java=parser()
    versions=rows("versions") if batch is None else [json.loads(l) for l in (batch/"versions.jsonl").read_text(encoding="utf-8").splitlines()]
    cache={}
    failures=[]
    for v in versions:
        key=v["cve_id"],v["commit"],v["file_path"]
        if key not in cache:
            content=git(repos/key[0],"show",key[1]+":"+key[2])
            tree=java.parse(content)
            require(not tree.root_node.has_error,"Parse error: "+str(key))
            nodes=[]
            def walk(node):
                if node.type in ("method_declaration","constructor_declaration","compact_constructor_declaration"):
                    name=node.child_by_field_name("name")
                    nodes.append((node.start_point.row+1,node.end_point.row+1,content[name.start_byte:name.end_byte].decode()))
                for child in node.named_children:
                    walk(child)
            walk(tree.root_node)
            cache[key]=nodes
        expected_name=v["syntactic_signature"].split("#",1)[1].split("(",1)[0]
        matches=[n for n in cache[key] if n==(v["start_line"],v["end_line"],expected_name)]
        if not matches:
            failures.append(dict(sample_id=v["sample_id"],expected=[v["start_line"],v["end_line"],expected_name]))
    return dict(checked_versions=len(versions),matched_versions=len(versions)-len(failures),failures=failures,
                scope="AST declaration name and exact start/end line boundaries; parameter type resolution and caller semantics remain unverified.")
