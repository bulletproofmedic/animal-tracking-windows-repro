from __future__ import annotations
import json,re,subprocess
from collections import Counter
from pathlib import Path
from typing import Any
MANIFEST='IMPLEMENTATION_SOURCE_MANIFEST.json'; REPOSITORY='synthetic/manifest-repository'; HEX40=re.compile(r'^[0-9a-f]{40}$')
def text(root:Path,*a:str)->str:return subprocess.check_output(['git',*a],cwd=root,text=True,encoding='utf-8').strip()
def raw(root:Path,*a:str)->bytes:return subprocess.check_output(['git',*a],cwd=root)
def commit(root:Path,ref:str)->str:return text(root,'rev-parse','--verify',f'{ref}^{{commit}}')
def tree(root:Path,ref:str)->str:return text(root,'rev-parse','--verify',f'{ref}^{{tree}}')
def parents(root:Path,ref:str)->list[str]:return text(root,'rev-list','--parents','-n','1',ref).split()[1:]
def category(p:str)->str:
 if p.startswith('.github/workflows/'):return 'CI_WORKFLOW'
 if '/migrations/' in p or p.startswith('migrations/'):return 'MIGRATION'
 if p.startswith('src/'):return 'APPLICATION_SOURCE'
 if p.startswith('tests/'):return 'TEST'
 if p.startswith('requirements/') or p.endswith(('.lock','lock.json')):return 'DEPENDENCY_LOCK'
 if p.startswith('scripts/'):return 'VALIDATION_SCRIPT'
 if p.startswith('docs/governance/'):return 'GOVERNANCE'
 if p.startswith(('docs/remediation/','docs/audits/')):return 'EVIDENCE'
 if '/fixtures/' in p or p.startswith('fixtures/'):return 'FIXTURE'
 if p.startswith(('proofs/','ios/')):return 'BOUNDED_PROOF'
 if p.startswith('docs/'):return 'DOCUMENTATION'
 return 'CONFIGURATION'
def paths(root:Path,source:str)->list[str]:
 out=[]
 for rec in raw(root,'ls-tree','-r','-z','--full-tree',source).split(b'\0'):
  if not rec:continue
  meta,name=rec.split(b'\t',1); _,kind,_=meta.decode().split(); p=name.decode('utf-8')
  if kind!='blob':raise RuntimeError(f'unsupported {kind} at {p}')
  if p!=MANIFEST:out.append(p)
 out.sort()
 if len(out)!=len(set(out)):raise RuntimeError('duplicate path')
 return out
def build(root:Path,source_ref:str,base_ref:str,state:str)->dict[str,Any]:
 source,base=commit(root,source_ref),commit(root,base_ref)
 if subprocess.run(['git','merge-base','--is-ancestor',base,source],cwd=root).returncode:raise RuntimeError('base not ancestor')
 ps=paths(root,source); groups={}
 for p in ps:
  d,n=p.rsplit('/',1) if '/' in p else ('',p);groups.setdefault(d,[]).append(n)
 counts=Counter(category(p) for p in ps)
 return {'schema_version':5,'manifest_format':'ANIMAL_TRACKING_IMPLEMENTATION_SOURCE_MANIFEST','binding_mode':'GIT_TREE_MERKLE_PATH_INVENTORY','state':state,'repository':REPOSITORY,'source_commit':source,'source_git_tree':tree(root,source),'source_base_commit':base,'authorized_scope':'Release 1 only','path_inventory':[{'directory':d,'entries':groups[d]} for d in sorted(groups)],'summary':{'total_file_count':len(ps),'count_by_category':dict(sorted(counts.items())),'excluded_entry_count':1},'excluded_entries':[{'path':MANIFEST,'reason':'self-referential output'}]}
def flatten(groups:list[dict])->list[str]:
 out=[]
 for g in groups:
  d=g['directory']; entries=g['entries']
  if entries!=sorted(entries):raise ValueError('unsorted entries')
  out.extend(f'{d}/{n}' if d else n for n in entries)
 return out
def validate(root:Path,payload:dict,base_ref:str,state:str,context:str,head_ref:str,manifest_file:Path)->list[str]:
 e=[]; required={'schema_version','manifest_format','binding_mode','state','repository','source_commit','source_git_tree','source_base_commit','authorized_scope','path_inventory','summary','excluded_entries'}
 if set(payload)!=required:e.append('schema')
 for k,v in {'schema_version':5,'manifest_format':'ANIMAL_TRACKING_IMPLEMENTATION_SOURCE_MANIFEST','binding_mode':'GIT_TREE_MERKLE_PATH_INVENTORY','state':state,'repository':REPOSITORY,'authorized_scope':'Release 1 only'}.items():
  if payload.get(k)!=v:e.append(k)
 source=payload.get('source_commit');base=commit(root,base_ref)
 if not isinstance(source,str) or not HEX40.fullmatch(source):e.append('source syntax');return e
 try:source=commit(root,source)
 except subprocess.CalledProcessError:e.append('source resolve');return e
 if payload.get('source_base_commit')!=base:e.append('base')
 if payload.get('source_git_tree')!=tree(root,source):e.append('tree')
 if subprocess.run(['git','merge-base','--is-ancestor',base,source],cwd=root).returncode:e.append('ancestry')
 expected=paths(root,source)
 try:listed=flatten(payload.get('path_inventory',[]))
 except Exception:e.append('inventory schema');listed=[]
 if listed!=sorted(listed):e.append('inventory order')
 if len(listed)!=len(set(listed)):e.append('duplicate')
 if set(expected)-set(listed):e.append('missing')
 if set(listed)-set(expected):e.append('extra')
 counts=Counter(category(p) for p in listed)
 if payload.get('summary')!={'total_file_count':len(expected),'count_by_category':dict(sorted(counts.items())),'excluded_entry_count':1}:e.append('summary')
 if payload.get('excluded_entries')!=[{'path':MANIFEST,'reason':'self-referential output'}]:e.append('exclusion')
 head,checkout=commit(root,head_ref),commit(root,'HEAD'); hp=parents(root,head); first=hp[0] if hp else None
 changed=[p for p in text(root,'diff','--name-only','--no-renames',source,head).splitlines() if p]
 if first!=source:e.append('head source parent')
 if changed!=[MANIFEST]:e.append('head changed paths')
 try:
  if raw(root,'show',f'{head}:{MANIFEST}')!=manifest_file.read_bytes():e.append('head manifest bytes')
 except Exception:e.append('head manifest bytes')
 cp=parents(root,checkout)
 if context=='exact-head':
  if checkout!=head:e.append('exact head')
 elif context=='merge-ref':
  if checkout==head:e.append('merge distinct')
  if len(cp)<2:e.append('merge parents')
  if head not in cp:e.append('merge direct parent')
 else:e.append('context')
 return e
