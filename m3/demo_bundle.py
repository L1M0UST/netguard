"""Explicit file producer for M3 integration testing; not imported by M3."""
import argparse
import hashlib
import os
from workspace_io import Workspace, atomic_json

def produce(root, task_id):
    workspace = Workspace(root)
    temporary = workspace.task_path('m2','STAGING',task_id)
    target = workspace.task_path('m2','READY',task_id)
    temporary.mkdir(parents=True,exist_ok=True)
    event_id = 'event-' + task_id
    bundle = {'schema_version':'AttackChainBundle.v1','task_id':task_id,
      'versions':{'rule_version':'demo','model_version':'disabled','prompt_version':'demo','code_commit':'demo','threshold_version':'demo'},
      'degraded':True,
      'evidence':[{'event_id':event_id,'summary':'演示：SSH 认证重复失败','source':'192.0.2.10','target':'198.51.100.20','timestamp':'2026-09-17T10:00:00Z'}],
      'alerts':[{'alert_id':'alert-'+task_id,'title':'演示凭证攻击','severity':'high','source':'192.0.2.10','target':'198.51.100.20','tactic':'Credential Access','technique':'T1110','confidence':0.85,'timestamp':'2026-09-17T10:00:00Z','event_ids':[event_id]}],
      'chains':[{'chain_id':'chain-'+task_id,'severity':'high','stages':[{'stage_id':'stage-1','tactic':'Credential Access','technique':'T1110','confidence':0.85,'time_range':['2026-09-17T10:00:00Z','2026-09-17T10:01:00Z'],'evidence_event_ids':[event_id]}],'edges':[]}],
      'profiles':[{'ip':'192.0.2.10','domains':[],'urls':[],'hashes':[],'victims':['198.51.100.20'],'attack_types':['凭证攻击'],'ioc_hits':[],'chain_ids':['chain-'+task_id],'evidence_refs':[event_id]}],
      'metrics':{'raw_count':10000,'denoised_count':100,'suspicious_count':10,'duration_seconds':3},
      'report':{'title':'文件联调演示报告','summary':'这是固定 Fake Bundle，未分析上传内容。','recommended_actions':[{'text':'核查认证日志；本演示不证明入侵成功。','source':'rule_based'}]}}
    atomic_json(temporary/'bundle.json',bundle)
    atomic_json(temporary/'manifest.json',{'schema_version':'ResultManifest.v1','task_id':task_id,'sha256':hashlib.sha256((temporary/'bundle.json').read_bytes()).hexdigest()})
    target.parent.mkdir(parents=True,exist_ok=True)
    os.rename(temporary,target)
    atomic_json(workspace.task_path('m2','STATUS',task_id)/'status.json',{'schema_version':'Status.v1','task_id':task_id,'state':'DEGRADED','progress':100,'message':'演示结果已投递；LLM 未启用'})

if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('task_id')
    parser.add_argument('--workspace',default='shared_workspace')
    args=parser.parse_args()
    produce(args.workspace,args.task_id)
