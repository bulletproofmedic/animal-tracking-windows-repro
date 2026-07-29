from __future__ import annotations
import json,os,shutil,subprocess,tempfile
from pathlib import Path
from manifest_ci_candidate import MANIFEST,build,validate
STATE='R1_SECURITY_EVENTS_MANIFEST_CONTROL_SOURCE';HERE=Path(__file__).resolve().parent
def run(root,*a,check=True):return subprocess.run(a,cwd=root,check=check,text=True,capture_output=True)
def out(root,*a):return subprocess.check_output(a,cwd=root,text=True).strip()
def commit(root,msg):run(root,'git','add','-A');run(root,'git','-c','user.name=Diagnostic','-c','user.email=d@example.invalid','commit','-q','-m',msg);return out(root,'git','rev-parse','HEAD')
def checkout(root,ref):run(root,'git','checkout','--detach','-q',ref)
def main():
 with tempfile.TemporaryDirectory(prefix='cf004-v5-') as td:
  r=Path(td)/'repo';r.mkdir();run(r,'git','init','-q');run(r,'git','config','core.autocrlf','false')
  for d in ['src/pkg','tests','docs','scripts','.github/workflows']:(r/d).mkdir(parents=True,exist_ok=True)
  (r/'src/pkg/app.py').write_text('VALUE=1\n');(r/'tests/test_app.py').write_text('def test_x(): assert True\n');(r/'docs/readme.md').write_text('# synthetic\n')
  base=commit(r,'base');shutil.copy2(HERE/'manifest_ci_candidate.py',r/'scripts/manifest_ci_candidate.py');(r/'.github/workflows/ci.yml').write_text('name: synthetic\n');source=commit(r,'source')
  payload=build(r,source,base,STATE);(r/MANIFEST).write_text(json.dumps(payload,indent=2)+'\n',newline='\n');valid=commit(r,'manifest');valid_text=(r/MANIFEST).read_text();results=[]
  def rec(name,expected,errors):results.append({'name':name,'expected':expected,'actual':'PASS' if not errors else 'FAIL','ok':(not errors)==(expected=='PASS')})
  checkout(r,valid);rec('positive_exact_head','PASS',validate(r,json.loads(valid_text),base,STATE,'exact-head',valid,r/MANIFEST))
  def mutation(name,change):
   checkout(r,source);p=json.loads(valid_text);change(p);(r/MANIFEST).write_text(json.dumps(p,indent=2)+'\n',newline='\n');h=commit(r,name);rec(name,'FAIL',validate(r,p,base,STATE,'exact-head',h,r/MANIFEST))
  mutation('missing_path',lambda p:(p['path_inventory'][0].__setitem__('entries',p['path_inventory'][0]['entries'][1:]),p['summary'].__setitem__('total_file_count',p['summary']['total_file_count']-1)))
  mutation('extra_path',lambda p:(p['path_inventory'][0]['entries'].append('zz-extra.txt'),p['path_inventory'][0]['entries'].sort(),p['summary'].__setitem__('total_file_count',p['summary']['total_file_count']+1)))
  mutation('stale_source_tree',lambda p:p.__setitem__('source_git_tree','0'*40));mutation('stale_state',lambda p:p.__setitem__('state','STALE'));mutation('stale_source_identity',lambda p:p.__setitem__('source_commit',base))
  mutation('category_summary_mismatch',lambda p:p['summary']['count_by_category'].__setitem__('APPLICATION_SOURCE',p['summary']['count_by_category']['APPLICATION_SOURCE']+1))
  checkout(r,valid);(r/'src/pkg/app.py').write_text('VALUE=2\n');unexpected=commit(r,'unexpected');rec('unexpected_source_change','FAIL',validate(r,json.loads(valid_text),base,STATE,'exact-head',unexpected,r/MANIFEST))
  checkout(r,base);(r/'side.txt').write_text('side\n');side=commit(r,'side');t=out(r,'git','rev-parse',f'{valid}^{{tree}}');env=os.environ.copy();env.update({'GIT_AUTHOR_NAME':'D','GIT_AUTHOR_EMAIL':'d@e.invalid','GIT_COMMITTER_NAME':'D','GIT_COMMITTER_EMAIL':'d@e.invalid'});merge=subprocess.check_output(['git','commit-tree',t,'-p',valid,'-p',side,'-m','merge'],cwd=r,text=True,env=env).strip();checkout(r,merge);(r/MANIFEST).write_text(valid_text,newline='\n');rec('true_two_parent_merge_ref','PASS',validate(r,json.loads(valid_text),base,STATE,'merge-ref',valid,r/MANIFEST));checkout(r,valid);rec('merge_ref_on_exact_head','FAIL',validate(r,json.loads(valid_text),base,STATE,'merge-ref',valid,r/MANIFEST))
  summary={'schema':'CF004_PUBLIC_WINDOWS_MATRIX_V2','test_count':len(results),'pass_count':sum(x['ok'] for x in results),'all_expected':all(x['ok'] for x in results),'results':results};print(json.dumps(summary,indent=2));raise SystemExit(0 if summary['all_expected'] else 1)
if __name__=='__main__':main()
