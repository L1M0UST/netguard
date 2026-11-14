"""M3-owned file exchange adapter. Wire fields are a local v1 draft for review."""
import hashlib
import json
import os
import re
import shutil
import uuid
from pathlib import Path
from pydantic import BaseModel, Field, model_validator, ConfigDict
from typing import Literal

class WireModel(BaseModel):
    model_config = ConfigDict(extra='allow')

class Stage(WireModel):
    stage_id: str
    tactic: str
    technique: str
    evidence_event_ids: list[str] = Field(min_length=1)
    confidence: float = Field(ge=0, le=1)
    time_range: list[str] = Field(min_length=2, max_length=2)

class Chain(WireModel):
    chain_id: str
    severity: Literal['info', 'low', 'medium', 'high', 'critical']
    stages: list[Stage]
    edges: list[tuple[str, str]] = Field(default_factory=list)

class Bundle(WireModel):
    schema_version: Literal['AttackChainBundle.v1']
    task_id: str
    alerts: list[dict]
    chains: list[Chain]
    evidence: list[dict]
    profiles: list[dict] = Field(default_factory=list)
    metrics: dict = Field(default_factory=dict)
    report: dict = Field(default_factory=dict)
    degraded: bool = False
    versions: dict[str, str]

    @model_validator(mode='after')
    def validate_references(self):
        required = {'rule_version','model_version','prompt_version','code_commit','threshold_version'}
        if not required <= self.versions.keys() or any(not self.versions[k].strip() for k in required):
            raise ValueError('missing processing versions')
        if any(not isinstance(e.get('event_id'), str) or not e['event_id'] for e in self.evidence):
            raise ValueError('evidence lacks event_id')
        ids = [e['event_id'] for e in self.evidence]
        known = set(ids)
        if len(ids) != len(set(ids)):
            raise ValueError('duplicate event_id')
        if len({c.chain_id for c in self.chains}) != len(self.chains):
            raise ValueError('duplicate chain_id')
        alert_ids = [a.get('alert_id') for a in self.alerts]
        if any(not isinstance(a,str) or not a for a in alert_ids) or len(set(alert_ids)) != len(alert_ids):
            raise ValueError('invalid or duplicate alert_id')
        for chain in self.chains:
            stage_ids = {s.stage_id for s in chain.stages}
            if len(stage_ids) != len(chain.stages):
                raise ValueError('duplicate stage_id')
            for stage in chain.stages:
                if not set(stage.evidence_event_ids) <= set(ids):
                    raise ValueError('stage refers to missing evidence')
            if any(a not in stage_ids or b not in stage_ids for a,b in chain.edges):
                raise ValueError('edge refers to missing stage')
        for alert in self.alerts:
            if not isinstance(alert.get('title'), str) or alert.get('severity') not in {'info','low','medium','high','critical'}:
                raise ValueError('alert requires title and valid severity')
            if 'confidence' in alert and (not isinstance(alert['confidence'], (int,float)) or not 0 <= alert['confidence'] <= 1):
                raise ValueError('invalid alert confidence')
            if not alert.get('event_ids') or not set(alert['event_ids']) <= set(ids):
                raise ValueError('alert lacks valid event_ids')
        for profile in self.profiles:
            if not profile.get('evidence_refs') or not set(profile['evidence_refs']) <= known:
                raise ValueError('profile lacks valid evidence_refs')
            if not set(profile.get('chain_ids', [])) <= {c.chain_id for c in self.chains}:
                raise ValueError('profile refers to missing chain')
            for relation in profile.get('relationships', []):
                if not relation.get('evidence_refs') or not set(relation['evidence_refs']) <= known:
                    raise ValueError('relationship lacks evidence_refs')
        for action in self.report.get('recommended_actions', []):
            if action.get('source') not in {'rule_based','knowledge_base','llm_generated','analyst_verified'}:
                raise ValueError('recommendation lacks source')
        return self

def atomic_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    with temporary.open('w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporary, path)

class Workspace:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self._cache = {}

    def task_path(self, producer, state, task_id):
        if not re.fullmatch(r'[a-zA-Z0-9_-]+', task_id):
            raise ValueError('invalid task_id')
        return self.root / producer / state / task_id

    def publish(self, task, records, data_dir):
        temporary = self.task_path('m3', 'STAGING', task['task_id'])
        target = self.task_path('m3', 'READY', task['task_id'])
        temporary.mkdir(parents=True, exist_ok=False)
        source_files = []
        for record in records:
            destination = temporary / record['file_id']
            shutil.copyfile(Path(data_dir) / record['file_id'], destination)
            with destination.open('rb+') as handle:
                digest = hashlib.file_digest(handle,'sha256').hexdigest()
                os.fsync(handle.fileno())
            if digest != record['sha256']:
                raise ValueError('uploaded file checksum mismatch')
            source_files.append({**record, 'path':record['file_id']})
        manifest = {'schema_version':'TaskManifest.v1','task_id':task['task_id'], 'created_at':task['created_at'], 'source_files':source_files,'user_prompt':task['query'], 'analysis_mode':task.get('analysis_mode', 'hybrid'), 'versions':{k:os.getenv('NETGUARD_'+k.upper(),'unconfigured') for k in ['rule_version','model_version','prompt_version','code_commit','threshold_version']}}
        atomic_json(temporary / 'manifest.json', manifest)
        target.parent.mkdir(parents=True, exist_ok=True)
        os.rename(temporary,target)
        return manifest

    def read_status(self, module, task_id):
        path = self.task_path(module,'STATUS',task_id) / 'status.json'
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding='utf-8'))
        if data.get('schema_version') != 'Status.v1' or data.get('task_id') != task_id:
            raise ValueError('status version/task mismatch')
        if data.get('state') not in {'QUEUED','RUNNING','COMPLETED','FAILED','DEGRADED'}:
            raise ValueError('invalid stage status')
        if not 0 <= data.get('progress',-1) <= 100:
            raise ValueError('invalid stage progress')
        return data

    def read_bundle(self, task_id):
        directory = self.task_path('m2','READY',task_id)
        if not directory.exists():
            self._cache.pop(task_id, None)
            return None
        signature = tuple((p.stat().st_mtime_ns, p.stat().st_size) for p in (directory/'manifest.json', directory/'bundle.json'))
        cached = self._cache.get(task_id)
        if cached and cached[0] == signature:
            return cached[1]
        manifest = json.loads((directory / 'manifest.json').read_text(encoding='utf-8'))
        if manifest.get('task_id') != task_id or manifest.get('schema_version') != 'ResultManifest.v1':
            raise ValueError('result manifest mismatch')
        payload = (directory / 'bundle.json').read_bytes()
        if hashlib.sha256(payload).hexdigest() != manifest.get('sha256'):
            raise ValueError('result checksum mismatch')
        bundle = Bundle.model_validate_json(payload)
        if bundle.task_id != task_id:
            raise ValueError('bundle task mismatch')
        value = bundle.model_dump()
        self._cache[task_id] = (signature, value)
        return value
