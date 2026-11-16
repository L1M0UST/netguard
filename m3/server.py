"""M3 browser-facing BFF using the v2.0 shared-workspace file protocol.

M3 creates manifests and reads validated M1/M2 files; it does not call the
analysis modules over HTTP, RPC, gRPC, Redis, or an internal mock provider.
"""
import asyncio
import hashlib
import io
import json
import uuid
import sqlite3
import os
import threading
import time
from contextlib import asynccontextmanager
from m3_services import validate_upload, answer_question, summary, redact, redact_value
from retention import expire_uploads
from workspace_io import Workspace
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, UploadFile, HTTPException
from fastapi.responses import FileResponse, StreamingResponse, Response
from pydantic import BaseModel, Field
from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from contracts import CandidateAlert, AttackChain, ProgressEvent

ROOT = Path(__file__).parent
DATA = Path(os.getenv('NETGUARD_DATA_DIR', str(ROOT / 'data')))
WORKSPACE = Workspace(os.getenv('NETGUARD_WORKSPACE',str(ROOT / 'shared_workspace')))
DATA.mkdir(exist_ok=True)
STATE_LOCK = threading.RLock()
_M1_RISK_CACHE = {}


def legacy_m1_risk_detail(task_id: str) -> dict:
    """Backfill risk observations for older tasks whose Status.v1 lacks detail."""
    root = WORKSPACE.root / 'm1' / 'ready' / f'batch-{task_id}'
    if not root.is_dir(): return {}
    run_dir = next((path for path in root.iterdir() if path.is_dir() and (path / 'batch.json').is_file()), None)
    if run_dir is None: return {}
    batch_path = run_dir / 'batch.json'
    try:
        batch = json.loads(batch_path.read_text(encoding='utf-8'))
        metrics = (batch.get('status') or {}).get('metrics') or {}
        if metrics.get('session_risk_counts'):
            return {'session_risk_counts': metrics['session_risk_counts'],
                    'informational_sessions': metrics.get('informational_sessions', metrics['session_risk_counts'].get('info', 0))}
        artifact = (batch.get('artifacts') or {}).get('all_sessions')
        data_path = run_dir / str(artifact or '')
        if not data_path.is_file(): return {}
        stamp = (str(data_path), data_path.stat().st_mtime_ns)
        if task_id in _M1_RISK_CACHE and _M1_RISK_CACHE[task_id][0] == stamp:
            return _M1_RISK_CACHE[task_id][1]
        import pyarrow.parquet as parquet
        scores = parquet.read_table(data_path, columns=['risk_score']).column('risk_score').to_pylist()
        counts = {'info': 0, 'low': 0, 'medium': 0, 'high': 0}
        for score in scores:
            value = int(score or 0)
            counts['info' if value < 20 else 'low' if value < 45 else 'medium' if value < 75 else 'high'] += 1
        detail = {'session_risk_counts': counts, 'informational_sessions': counts['info']}
        _M1_RISK_CACHE[task_id] = (stamp, detail)
        return detail
    except (OSError, ValueError, KeyError, TypeError, ImportError):
        return {}


@asynccontextmanager
async def lifespan(app):
    async def maintenance():
        while True:
            await asyncio.sleep(60)
            try:
                removed=expire_uploads(files,tasks,DATA,WORKSPACE,float(os.getenv('NETGUARD_RAW_TTL_HOURS','72')))
                if removed:
                    save_state()
                    audit('raw.expired','',str(len(removed)))
            except (OSError, ValueError):
                pass
    job=asyncio.create_task(maintenance())
    try:
        yield
    finally:
        job.cancel()
        try:
            await job
        except asyncio.CancelledError:
            pass

app = FastAPI(title='NetGuard M3 BFF', version='0.1.0', lifespan=lifespan)
from fastapi.middleware.gzip import GZipMiddleware  # noqa: E402  大 bundle 响应压缩（文本压缩率~90%）
app.add_middleware(GZipMiddleware, minimum_size=2048)

def slim_bundle(bundle):
    """任务列表用：剥离最重的 evidence、alerts、chains、victims、campaigns 与 graph
    （alerts 已在任务顶层，chains 以 chain_id+severity 摘要随任务顶层提供；
    详情接口 /tasks/{id} 仍提供全量）。"""
    if not bundle:
        return bundle
    return {k: v for k, v in bundle.items()
            if k not in ('evidence', 'alerts', 'chains', 'victims', 'campaigns', 'graph')}


def public_task(task):
    """对外输出：剥离 _raw_bundle（未脱敏原始结果包，且体积翻倍）。"""
    return {k: v for k, v in task.items() if k != '_raw_bundle'}


def list_item(task):
    """任务列表项：chains 只留 chain_id+severity。6577 链任务的完整列表曾达
    70MB+（chains 与 bundle.chains 双份全量），浏览器 15s 轮询一次即拖垮前端；
    完整 stages/confidence_card 由详情接口 /tasks/{id} 提供。"""
    item = public_task({k: v for k, v in task.items() if k not in ('bundle', '_raw_bundle')})
    item['chains'] = [{'chain_id': c['chain_id'], 'severity': c.get('severity'),
                       'signal_severity': c.get('signal_severity'),
                       'stage_count': len(c.get('stages') or []),
                       'risk_score': (c.get('confidence_card') or {}).get('score')}
                      for c in task.get('chains', [])]
    item.pop('chain', None)
    item['bundle'] = slim_bundle(task.get('bundle'))
    return item

STATE = DATA / 'state.sqlite3'
def save_state():
    with STATE_LOCK, sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, payload TEXT)')
        # bundle 体积可达几十 MB 且可由工作区文件重建，持久化时剥离，避免状态库膨胀拖垮启动
        light_tasks = {task_id: {k: v for k, v in task.items() if k not in ('bundle', '_raw_bundle')}
                       for task_id, task in tasks.items()}
        db.execute('INSERT OR REPLACE INTO state VALUES (1, ?)', (json.dumps({'files': files, 'tasks': light_tasks}),))

with sqlite3.connect(STATE) as db:
    db.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY, payload TEXT)')
    record = db.execute('SELECT payload FROM state WHERE id=1').fetchone()
restored = json.loads(record[0]) if record else {}
files = restored.get('files', {})
# Do not expose tasks created by the pre-v2 in-process mock flow. M3 only
# presents tasks that have a shared-workspace transport contract.
tasks = {task_id: task for task_id, task in restored.get('tasks', {}).items()
         if task.get('transport') == 'files'}
jobs = set()
save_state()

class TaskInput(BaseModel):
    file_ids: list[str] = Field(min_length=1)
    query: str = ''
    analysis_mode: str = 'hybrid'

class ChatInput(BaseModel):
    task_id: str
    chain_id: str | None = None
    message: str = Field(min_length=1, max_length=4000)

def task_for(task_id):
    if task_id not in tasks:
        raise HTTPException(404, 'TASK_404')
    refresh_file_task(tasks[task_id])
    return tasks[task_id]

def event(name, data):
    return f'event: {name}\ndata: {json.dumps(data, ensure_ascii=False)}\n\n'

@app.post('/api/v1/files')
async def upload(file: UploadFile):
    if Path(file.filename or '').suffix.lower() not in {'.csv', '.json', '.jsonl', '.pcap', '.pcapng', '.xlsx'}:
        raise HTTPException(400, 'FILE_400: 不支持该格式')
    file_id = uuid.uuid4().hex
    path = DATA / file_id
    size, digest = 0, hashlib.sha256()
    try:
        with path.open('wb') as output:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > 2 * 1024**3:
                    raise HTTPException(413, '文件超过 2 GB')
                digest.update(chunk)
                output.write(chunk)
        if not size:
            raise HTTPException(400, '文件为空')
        try:
            validate_upload(path, file.filename)
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    files[file_id] = dict(file_id=file_id, filename=file.filename, size=size, sha256=digest.hexdigest(),uploaded_at_epoch=time.time())
    save_state()
    return files[file_id]

def audit(action, task_id, detail=''):
    detail = json.dumps({'actor':os.getenv('NETGUARD_ACTOR', 'local-user'), 'detail':detail}, ensure_ascii=False)
    with sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS audit (at TEXT, action TEXT, task_id TEXT, detail TEXT)')
        db.execute('INSERT INTO audit VALUES (?,?,?,?)',(datetime.now(timezone.utc).isoformat(), action, task_id, detail))

def refresh_file_task(task):
    if task.get('transport') != 'files':
        return
    try:
        with STATE_LOCK:  # 任务字典被 SSE/轮询并发读写，统一加锁
            statuses = [{**s, 'module':module} for module in ['m1','m2'] if (s := WORKSPACE.read_status(module,task['task_id']))]
            task['module_statuses'] = statuses
            if any(s['state']=='FAILED' for s in statuses):
                task.pop('bundle', None)
                task.update(status='failed',stage='模块处理失败；查看模块状态',alerts=[],chains=[],chain=None)
                return
            bundle = WORKSPACE.read_bundle(task['task_id'])
            if bundle:
                if task.get('_raw_bundle') is not bundle:
                    # 结果包未变化时（Workspace 缓存命中返回同一对象）复用上次加工结果，
                    # 避免 6577 链级 bundle 在每次 0.25s 轮询时重复脱敏/推导。
                    task['_raw_bundle'] = bundle
                    processed = redact_value(bundle)
                    # 旧结果包曾把前置规则强度强行覆盖综合风险等级，造成低危为 0，
                    # 且与 confidence_card.severity 冲突。读取时兼容修正，原规则强度
                    # 保留为 signal_severity，便于用户追溯而不污染最终分布。
                    chain_severity = {}
                    for chain in processed.get('chains', []):
                        grounded = (chain.get('confidence_card') or {}).get('severity')
                        previous = chain.get('severity')
                        if grounded in {'info', 'low', 'medium', 'high', 'critical'}:
                            if previous != grounded:
                                chain['signal_severity'] = previous
                            chain['severity'] = grounded
                        chain_severity[chain.get('chain_id')] = chain.get('severity')
                    for alert in processed.get('alerts', []):
                        previous = alert.get('severity')
                        grounded = chain_severity.get(alert.get('chain_id'))
                        if grounded:
                            if previous != grounded:
                                alert['signal_severity'] = previous
                            alert['severity'] = grounded
                    m1_detail = next((s.get('detail', {}) for s in statuses if s.get('module') == 'm1'), {})
                    if not m1_detail.get('session_risk_counts'):
                        m1_detail = legacy_m1_risk_detail(task['task_id'])
                    info_count = int(m1_detail.get('informational_sessions', 0) or 0)
                    processed.setdefault('metrics', {})['informational_sessions'] = info_count
                    processed['metrics']['session_risk_counts'] = m1_detail.get('session_risk_counts') or {}
                    sev_counts = {key: 0 for key in ('critical', 'high', 'medium', 'low', 'info')}
                    for alert in processed.get('alerts', []):
                        sev_counts[alert.get('severity', 'info')] = sev_counts.get(alert.get('severity', 'info'), 0) + 1
                    processed.setdefault('metrics', {})['severity_counts'] = sev_counts
                    statistics = processed.setdefault('report', {}).setdefault('statistics', {})
                    statistics.update({f'{key}_count': value for key, value in sev_counts.items()})
                    report = processed['report']
                    report.setdefault('source_summary', report.get('summary') or '')
                    metrics = processed.get('metrics', {})
                    multistage = metrics.get('multistage_chains') or statistics.get('multistage_chains') or 0
                    report['summary'] = (
                        f"本批接入原始事件 {metrics.get('raw_count', '—')} 条，经降噪识别可疑事件 "
                        f"{metrics.get('suspicious_count', '—')} 条，最终形成 {len(processed.get('alerts', []))} 条告警、"
                        f"{len(processed.get('chains', []))} 条攻击链，其中多阶段链 {multistage} 条。"
                        f"综合风险分布为：严重 {sev_counts['critical']} 条、高危 {sev_counts['high']} 条、"
                        f"中危 {sev_counts['medium']} 条、低危 {sev_counts['low']} 条、信息级告警 {sev_counts['info']} 条。"
                        f"另有 {info_count} 个信息级观察会话（全量会话风险分低于 20，不计入告警）。"
                        "处置时优先调查多阶段链，再结合风险分、受影响资产和原始证据逐项核实。"
                    )
                    evidence_index = {e['event_id']: e for e in processed['evidence']}
                    processed['alerts'] = [{**a,
                        'schema_version': a.get('schema_version', 'CandidateAlert.v1'),
                        'mitre': a.get('mitre') or a.get('technique'),
                        # M2 告警以 attacker_ips/victim_ips 数组承载实体；补齐
                        # source/target 标量别名，前端检索与展示统一取用。
                        'source': a.get('source') or next(iter(a.get('attacker_ips') or []), None),
                        'target': a.get('target') or next(iter(a.get('victim_ips') or []), None),
                        'attacker_ips': a.get('attacker_ips') or ([a['source']] if a.get('source') else []),
                        'victim_ips': a.get('victim_ips') or ([a['target']] if a.get('target') else []),
                        'evidence': '; '.join(evidence_index[e].get('summary','') for e in a.get('event_ids', [])),
                    } for a in processed['alerts']]
                    task['alerts'] = processed['alerts']
                    task['bundle'] = processed
                    task['chains'] = [{**c,
                        'schema_version': c.get('schema_version', 'AttackChain.v1'),
                        'task_id':task['task_id'],
                        'nodes':[s['stage_id'] for s in c['stages']],
                        'evidence_ids':list(dict.fromkeys(e for s in c['stages'] for e in s['evidence_event_ids'])),
                        'evidence_event_ids':list(dict.fromkeys(e for s in c['stages'] for e in s['evidence_event_ids'])),
                        'explanation':processed['report'].get('summary','')
                    } for c in processed['chains']]
                    task['chain'] = next(iter(task['chains']),None)
                task.update(status='completed',progress=100,degraded=task['bundle']['degraded'],stage='结果已校验（降级）' if task['bundle']['degraded'] else '结果已校验')
            elif statuses:
                task.pop('bundle', None)
                task.update(alerts=[], chains=[], chain=None)
                task.update(status='running',progress=min(99,round(sum(s['progress'] for s in statuses)/2)),stage=statuses[-1].get('message','处理中'))
            else:
                task.pop('bundle', None)
                task.update(status='queued',progress=0,stage='等待分析流水线结果',alerts=[],chains=[],chain=None)
    except (ValueError, KeyError, TypeError, OSError) as error:
        task.pop('bundle', None)
        task.update(status='failed',stage='文件契约校验失败：'+str(error)[:200], alerts=[], chains=[], chain=None)

@app.post('/api/v1/tasks')
async def create_task(body: TaskInput):
    if any(f not in files for f in body.file_ids):
        raise HTTPException(400, 'FILE_400: 文件不存在')
    if any(files[f].get('raw_expired') for f in body.file_ids):
        raise HTTPException(410, '原始副本已按保留策略过期，请重新上传')
    modes = {'local', 'cloud', 'hybrid'}
    if body.analysis_mode not in modes:
        raise HTTPException(400, 'ANALYSIS_MODE_400: 仅支持 local、cloud 或 hybrid')
    task_id = uuid.uuid4().hex
    task = dict(task_id=task_id, file_ids=body.file_ids, query=body.query, analysis_mode=body.analysis_mode, filename=files[body.file_ids[0]]['filename'], created_at=datetime.now(timezone.utc).isoformat(), status='queued', progress=0, stage='排队中', mock=False, transport='files', alerts=[], chain=None, chains=[])
    try:
        WORKSPACE.publish(task,[files[f] for f in body.file_ids],DATA)
    except (ValueError,OSError) as error:
        raise HTTPException(400,'任务文件投递失败：'+str(error))
    task['stage']='等待分析流水线结果'
    tasks[task_id] = task
    save_state()
    audit('task.created',task_id, body.analysis_mode)
    return task

@app.post('/api/v1/tasks/{task_id}/retry')
async def retry_task(task_id: str):
    task = task_for(task_id)
    if task['status'] != 'failed':
        raise HTTPException(409, '只有失败任务可以重试')
    return await create_task(TaskInput(file_ids=task['file_ids'], query=task['query'], analysis_mode=task.get('analysis_mode', 'hybrid')))

@app.get('/api/v1/tasks')
def list_tasks():
    for task in tasks.values():
        refresh_file_task(task)
    # 列表不做全量 bundle/chains 序列化（6577 链级任务曾把列表撑到 70MB+）：
    # 指标卡/饼图/链计数只需要 metrics、report.summary 与 chain 摘要，
    # 完整 stages/confidence_card 由详情接口 /tasks/{id} 提供。
    return [list_item(task) for task in list(tasks.values())]

@app.get('/api/v1/tasks/{task_id}')
def get_task(task_id: str):
    task = dict(public_task(task_for(task_id)))
    # 顶层已提供 alerts/chains；bundle 内重复副本与 evidence 会让大任务响应翻倍。
    # 需要完整证据走 /bundle，单告警详情走 /alert/{id}。
    if isinstance(task.get('bundle'), dict):
        task['bundle'] = {k: v for k, v in task['bundle'].items()
                          if k not in ('evidence', 'alerts', 'chains')}
    return task

@app.get('/api/v1/tasks/{task_id}/alert/{alert_id}')
def alert_detail(task_id: str, alert_id: str):
    """轻量告警详情：告警 + 关联链 + 证据切片（KB 级响应，替代整包拉取）。"""
    task = task_for(task_id)
    bundle = task.get('bundle', {})
    alert = next((a for a in task.get('alerts', []) if a.get('alert_id') == alert_id), None)
    if not alert:
        raise HTTPException(404, '告警不存在')
    event_ids = set(alert.get('event_ids') or [])
    related = []
    for chain in bundle.get('chains', []):
        if chain.get('chain_id') == alert.get('chain_id') or any(
                event_ids.intersection(s.get('evidence_event_ids') or []) for s in chain.get('stages', [])):
            related.append({k: chain.get(k) for k in (
                'chain_id', 'severity', 'stages', 'edges', 'attacker_ips', 'victim_ips', 'confidence_card')})
    evidence = [e for e in bundle.get('evidence', []) if e.get('event_id') in event_ids]
    return {**alert, 'task_id': task_id, 'taskLabel': task.get('filename') or task_id,
            'related_chains': related, 'evidence': evidence,
            'recommended_actions': (bundle.get('report') or {}).get('recommended_actions', [])[:10]}

# ---- 单事件研判报告（cqsec 能力②激活；LLM 不可用回退确定性汇总） ----
_EVENT_REPORT_CACHE: dict = {}


def _event_report_lines(evidence_items, limit=8):
    """从证据行确定性构建模型输入明细（时间|URL|载荷摘要→类型）。

    证据索引没有 method/request_body 独立列：载荷从 M1 summary 的「载荷:」段截取，
    method 不写（避免把 POST 事件虚构成 GET）。全部过 redact() 防止载荷里的指令
    样式内容随提示词扩散。
    """
    lines = []
    for item in (evidence_items or [])[:limit]:
        summary = str(item.get('summary') or '')
        marker = summary.find('载荷:')
        payload = summary[marker + 3:].strip() if marker >= 0 else summary
        payload = payload.rsplit(' [', 1)[0]  # 去掉尾部「 [标签]」
        lines.append(f"  {str(item.get('timestamp') or '')[5:16].replace('T', ' ')}|"
                     f"{redact(str(item.get('url_path') or '/'))[:60]}|"
                     f"{redact(payload)[:50]}→{item.get('attack_type') or '未研判'}")
    return lines


def _deterministic_event_report(alert, evidence_items, bundle):
    """LLM 不可用时的单事件研判报告：四要素全部取自结果包既有字段，不调用任何模型。"""
    sev_cn = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '提示'}
    chain = next((c for c in bundle.get('chains', [])
                  if c.get('chain_id') == alert.get('chain_id')), None)
    card = (chain or {}).get('confidence_card') or {}
    stamps = sorted(str(e.get('timestamp') or '') for e in evidence_items if e.get('timestamp'))
    direction = (f"{(alert.get('attacker_ips') or ['未知来源'])[0]} → "
                 f"{(alert.get('victim_ips') or ['未知资产'])[0]}")
    atype = alert.get('attack_type') or '待研判'
    severity = sev_cn.get(alert.get('severity'), alert.get('severity') or '未分级')
    signal = sev_cn.get(alert.get('signal_severity'), '')
    overview = (f"疑似{atype}：{direction}。发生时间 {stamps[0][5:16] if stamps else '—'} ~ "
                f"{stamps[-1][5:16] if stamps else '—'}，关联证据 {len(evidence_items)} 条；"
                f"综合等级 {severity}"
                + (f"（规则信号 {signal}）" if signal and signal != severity else "")
                + f"，置信度 {round((alert.get('confidence') or 0) * 100)}%。")
    stage_parts = [f"  阶段{idx}：{_att_cn(stage.get('tactic'))} / {_att_cn(stage.get('technique'))}"
                   f"（证据 {len(stage.get('evidence_event_ids') or [])} 条）"
                   for idx, stage in enumerate((chain or {}).get('stages') or [], 1)]
    evidence_parts = [f"  {i + 1}. [{str(e.get('event_id') or '')[:8]}] "
                      f"{redact(str(e.get('summary') or ''))[:120]}"
                      for i, e in enumerate(evidence_items[:5])]
    risk = (f"风险分 {card.get('score', '—')}/100；风险依据："
            f"{redact(str(alert.get('risk_reason') or '当前结果未提供详细风险依据'))[:150]}。")
    technique = str(alert.get('technique') or alert.get('mitre') or '').split(' ')[0]
    actions = (bundle.get('report') or {}).get('recommended_actions', [])
    matched = [a for a in actions if technique and technique in (a.get('related_techniques') or [])]
    advice_parts = []
    for action in (matched or actions)[:3]:
        code = next((t for t in (action.get('related_techniques') or []) if t in ADVICE_CN), None)
        title, text = ADVICE_CN[code] if code else (str(action.get('title') or '建议'),
                                                    str(action.get('text') or ''))
        advice_parts.append(f"  · {title}：{redact(text)[:120]}")
    return "\n".join([
        f"【事件概述】{overview}",
        ("【攻击证据】" + ("\n".join(stage_parts) if stage_parts
                          else "  本告警未关联攻击链（单事件独立存在）。")
         + ("\n" + "\n".join(evidence_parts) if evidence_parts else "")),
        f"【风险等级】{risk}",
        ("【处置建议】" + ("\n".join(advice_parts) if advice_parts
                          else "  暂无结构化处置建议，请按攻击类型知识库处理。")),
    ])


@app.post('/api/v1/tasks/{task_id}/alert/{alert_id}/event-report')
def alert_event_report(task_id: str, alert_id: str):
    """单事件研判报告：本地垂域模型（能力②）生成四段研判；模型不可用时回退
    确定性汇总（同构四要素，来源诚实标注）。本地模型无云端额度成本。"""
    task = task_for(task_id)
    if task['status'] != 'completed':
        raise HTTPException(409, '任务尚未完成')
    alert = next((a for a in task.get('alerts', []) if a.get('alert_id') == alert_id), None)
    if not alert:
        raise HTTPException(404, '告警不存在')
    cached = _EVENT_REPORT_CACHE.get((task_id, alert_id))
    if cached:
        return {**cached, 'cached': True}
    bundle = task.get('bundle', {})
    event_ids = set(alert.get('event_ids') or [])
    evidence_items = [e for e in bundle.get('evidence', []) if e.get('event_id') in event_ids]
    src = (alert.get('attacker_ips') or ['未知来源'])[0]
    dst = (alert.get('victim_ips') or ['未知资产'])[0]
    stamps = sorted(str(e.get('timestamp') or '') for e in evidence_items if e.get('timestamp'))
    source, note, report = 'deterministic', '', None
    if os.getenv('NETGUARD_LLM_ENABLED', '0') == '1' and os.getenv('NETGUARD_LLM_PROTOCOL', '') == 'cqsec':
        try:
            from llm.cqsec import event_report as cqsec_event_report
            report = cqsec_event_report(src, dst, _event_report_lines(evidence_items),
                                        stamps[0][5:16] if stamps else '—',
                                        stamps[-1][5:16] if stamps else '—')
            source = 'cqsec'
        except Exception as exc:  # noqa: BLE001 - 模型离线/超时/空回复 → 确定性回退
            note = f'本地垂域模型不可用（{type(exc).__name__}），以下为确定性汇总'
            report = None
    if not report:
        report = _deterministic_event_report(alert, evidence_items, bundle)
    audit('report.event_report', task_id, alert_id)
    payload = {'alert_id': alert_id, 'task_id': task_id, 'source': source, 'note': note,
               'report': report, 'generated_at': datetime.now(timezone.utc).isoformat()}
    if len(_EVENT_REPORT_CACHE) >= 200:
        _EVENT_REPORT_CACHE.clear()
    _EVENT_REPORT_CACHE[(task_id, alert_id)] = payload
    return payload


@app.get('/api/v1/tasks/{task_id}/stream')
def progress(task_id: str):
    task = task_for(task_id)
    async def stream():
        previous = None
        while True:
            refresh_file_task(task)
            snapshot = (task['status'], task['progress'], task['stage'], json.dumps(task.get('module_statuses', [])))
            if snapshot != previous:
                yield event('progress', {**ProgressEvent(task_id=task_id, status=task['status'], progress=task['progress'], stage=task['stage']).model_dump(), 'module_statuses':task.get('module_statuses', [])})
                previous = snapshot
            if task['status'] in {'completed', 'failed'}:
                break
            await asyncio.sleep(.25)
    return StreamingResponse(stream(), media_type='text/event-stream', headers={'Cache-Control':'no-cache'})

@app.get('/api/v1/tasks/{task_id}/alerts')
def alerts(task_id: str):
    return task_for(task_id)['alerts']

@app.get('/api/v1/attack-chains/{chain_id}')
def chain(chain_id: str):
    for task in tasks.values():
        refresh_file_task(task)
        for item in task.get('chains',[]):
            if item['chain_id'] == chain_id:
                return item
        if task['chain'] and task['chain']['chain_id'] == chain_id:
            return task['chain']
    raise HTTPException(404, '攻击链不存在')

@app.post('/api/v1/chat')
def chat(body: ChatInput):
    task = task_for(body.task_id)
    if task['status'] != 'completed':
        raise HTTPException(409, '请等待任务完成')
    if body.chain_id and body.chain_id not in [c['chain_id'] for c in task.get('chains',[])]:
        raise HTTPException(404, '攻击链不属于当前任务')
    async def stream():
        yield event('status', {'message':'正在检索任务证据与知识来源'})
        answer, citations, degraded = await asyncio.to_thread(answer_question, task.get('bundle', {}), body.message, body.chain_id, ROOT/'knowledge')
        audit('chat.query',body.task_id,redact(body.message[:200]))
        with sqlite3.connect(STATE) as db:
            db.execute('CREATE TABLE IF NOT EXISTS chat_history (task_id TEXT, at TEXT, question TEXT, answer TEXT, citations TEXT)')
            db.execute('INSERT INTO chat_history VALUES (?,?,?,?,?)', (body.task_id, datetime.now(timezone.utc).isoformat(), redact(body.message), answer, json.dumps(citations)))
        for start in range(0, len(answer), 80):
            yield event('delta', {'text':answer[start:start+80]})
        yield event('evidence', {'items':citations})
        yield event('done', {'degraded': degraded})
    return StreamingResponse(stream(), media_type='text/event-stream')

@app.get('/api/v1/reports/{task_id}')
def report(task_id: str, format: str = 'json', chain_id: str | None = None):
    task = task_for(task_id)
    if task['status'] != 'completed':
        raise HTTPException(409, '任务尚未完成')
    audit('report.export',task_id,format)
    if format == 'json':
        bundle = task.get('bundle', {})
        chains = bundle.get('chains', [])
        if chain_id:
            chains = [chain for chain in chains if chain.get('chain_id') == chain_id]
            if not chains:
                raise HTTPException(404, '未找到指定攻击链')
        selected_chain_ids = {chain.get('chain_id') for chain in chains}
        alerts = bundle.get('alerts', [])
        if chain_id:
            alerts = [alert for alert in alerts if alert.get('chain_id') in selected_chain_ids]
        event_ids = {event_id for chain in chains for stage in chain.get('stages', [])
                     for event_id in stage.get('evidence_event_ids', [])}
        evidence = bundle.get('evidence', [])
        if chain_id:
            evidence = [item for item in evidence if item.get('event_id') in event_ids]
        profiles = bundle.get('profiles', [])
        if chain_id:
            profiles = [profile for profile in profiles
                        if selected_chain_ids.intersection(profile.get('chain_ids') or [])]
        # risk_score 的旧格式完整复制了 confidence_card，6577 条链会产生数 MB 冗余。
        # 导出时保留完整解释卡，同时把 risk_score 规范化为数值；不修改工作区原始产物。
        export_chains = []
        for chain in chains:
            exported = dict(chain)
            legacy_score = exported.get('risk_score')
            if isinstance(legacy_score, dict):
                if not exported.get('confidence_card'):
                    exported['confidence_card'] = legacy_score
                exported['risk_score'] = legacy_score.get('score')
            export_chains.append(exported)
        payload = {
            'export_version': 'NetGuardEvidencePackage.v1',
            'scope': 'attack_chain' if chain_id else 'task',
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'task': {key: task.get(key) for key in
                     ('task_id', 'filename', 'created_at', 'status', 'degraded')},
            'executive_summary': (bundle.get('report') or {}).get('summary'),
            'metrics': bundle.get('metrics', {}),
            'risk_distribution': summary(bundle).get('severity_counts', {}),
            'recommended_actions': (bundle.get('report') or {}).get('recommended_actions', []),
            'alerts': alerts,
            'attack_chains': export_chains,
            'attacker_profiles': profiles,
            'evidence': evidence,
            'versions': bundle.get('versions', {}),
        }
        stem = f'netguard-chain-{chain_id}' if chain_id else f'netguard-evidence-{task_id[:8]}'
        # 整任务证据包使用紧凑 JSON，链级导出继续保留缩进，兼顾体积和人工审阅。
        dump_options = {'ensure_ascii': False, 'indent': 2} if chain_id else {
            'ensure_ascii': False, 'separators': (',', ':')}
        return Response(json.dumps(redact_value(payload), **dump_options),
                        media_type='application/json',
                        headers={'Content-Disposition':f'attachment; filename="{stem}.json"'})
    if format != 'pdf':
        raise HTTPException(400, '仅支持 json/pdf')
    return Response(_build_pdf_report(task), media_type='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="netguard-risk-report-{task_id[:8]}.pdf"'})


def _esc(value):
    """动态文本 XML 转义：告警载荷可能含 <img onerror=...> 等真实攻击串，直接进 Paragraph 会被当标记解析。"""
    from xml.sax.saxutils import escape
    return escape(str(value if value is not None else ''))

PDF_FONT_NAME = 'STSong-Light'

def _pdf_styles():
    base = dict(fontName=PDF_FONT_NAME, fontSize=10.5, leading=16, textColor=colors.HexColor('#1f2937'))
    return {
        'title': ParagraphStyle('t', fontName=PDF_FONT_NAME, fontSize=20, leading=28, textColor=colors.HexColor('#1d4ed8')),
        'sub': ParagraphStyle('s', fontName=PDF_FONT_NAME, fontSize=9.5, leading=14, textColor=colors.HexColor('#6b7280')),
        'h1': ParagraphStyle('h1', fontName=PDF_FONT_NAME, fontSize=14, leading=20, spaceBefore=14, spaceAfter=6,
                             textColor=colors.HexColor('#111827')),
        'body': ParagraphStyle('b', **base),
        'cell': ParagraphStyle('c', fontName=PDF_FONT_NAME, fontSize=9, leading=13),
        'cellb': ParagraphStyle('cb', fontName=PDF_FONT_NAME, fontSize=9, leading=13, textColor=colors.white),
    }

def _pdf_table(data, widths, styles, header=True):
    table = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#d1d5db')),
             ('VALIGN', (0, 0), (-1, -1), 'TOP'),
             ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1d4ed8')),
             ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f4f6fb')])]
    table.setStyle(TableStyle(style))
    return table

# ATT&CK 战术/技术 → 中文（报告用，与前端展示层同源；未知回退"中文名+编号"或原文）
ATT_TACTIC_CN = {'TA0001':'初始访问','TA0002':'执行','TA0003':'持久化','TA0004':'权限提升','TA0005':'防御规避','TA0006':'凭证访问','TA0007':'发现与探测','TA0008':'横向移动','TA0009':'信息收集','TA0010':'数据外传','TA0011':'命令与控制','TA0012':'影响破坏','TA0043':'未归类'}
ATT_TECH_CN = {'T1190':'利用面向公众的应用程序漏洞','T1110':'暴力破解口令','T1046':'远程服务侦察','T1595':'主动扫描探测','T1059':'命令与脚本解释器执行','T1003':'凭据窃取','T1021':'远程服务登录','T1071':'应用层协议 C2','T1078':'使用有效账户','T1105':'工具与载荷传输','T1567':'经 Web 服务外传数据','T1041':'经 C2 通道外传数据','T1048':'经备用协议外传数据','T1486':'数据加密破坏','T1498':'网络泛洪 DoS','T1082':'系统信息探测','T1547':'开机自启持久化','T1562':'削弱安全防护','T1133':'外部远程服务','T1203':'客户端程序漏洞利用执行','T1068':'漏洞利用提权','Unclassified':'未归类行为'}
def _att_cn(raw):
    s = str(raw or '').strip()
    if not s: return ''
    code = s.split(' ')[0]
    cn = ATT_TACTIC_CN.get(code) or ATT_TECH_CN.get(code) or ATT_TECH_CN.get(s)
    return f'{cn}（{code}）' if (cn and code != cn) else (cn or s)
def _time_cn(raw):
    s = str(raw or '')
    return s.replace('T', ' ')[:16]
def _profile_cn(p):
    """由画像结构化字段生成中文概述（与 M2 英文 behavior_summary 同源，不虚构）。"""
    assets = len(p.get('target_assets') or [])
    parts = [f"对 {assets or '若干'} 个资产发起 {p.get('attack_count', '?')} 次攻击"]
    chains = len(p.get('chain_ids') or [])
    if chains: parts.append(f"横跨 {chains} 条攻击链")
    tac = list(dict.fromkeys([_att_cn(t).split('（')[0] for t in (p.get('tactics') or [])]))[:6]
    if tac: parts.append('涉及战术 ' + '、'.join(tac))
    return '；'.join(parts) + '。'

# 技术编号 → 中文处置建议（PDF 与单事件报告回退共用；与前端展示层同源）
ADVICE_CN = {
    'T1190': ('修补被利用的对外服务', '面向公网的应用被漏洞利用，立即修补受影响组件、下线受影响版本并验证已不可被外部访问。'),
    'T1110': ('启用多因子认证与登录限流', '存在认证爆破，强制 MFA、账号锁定/频率限制，达阈值即封禁来源。'),
    'T1567': ('实施出口数据防泄漏', '观测到对外数据传输，启用 DLP/出口过滤、限制上传目的地并对异常流量告警。'),
    'T1041': ('排查命令与控制外传通道', '疑似经 C2 通道外传，阻断该通道、留存流量元数据并核实外传数据。'),
    'T1048': ('监控备用协议外传', '疑似经 DNS/ICMP 等备用协议外传，强制出口管控并限制非法协议。'),
    'T1595': ('收敛对外暴露面', '移除不必要暴露端口、对入站连接限速并将扫描源纳入边界封禁。'),
    'T1046': ('限制并监控内网探测', '做网络分段、限制东西向流量，并对扫描特征告警。'),
    'T1059': ('约束命令与脚本解释器', '限制解释器仅用于授权管理路径，开启脚本块日志并对混淆命令告警。'),
    'T1003': ('保护凭据存储', '启用凭据防护、限制调试权限并轮换可能泄露的凭据。'),
    'T1071': ('阻断并检查命令与控制通道', '对已识别基础设施封禁，出口启用 TLS 检查并排查周期性外联。'),
}

def _victim_top(bundle):
    """高风险资产 Top：bundle['victims'] 优先；旧结果包没有该键时从 chains 确定性重建
    （与 assemble._build_victims 兜底同口径），保证历史任务 PDF 也有资产章。"""
    victims = bundle.get('victims') or []
    if victims:
        return victims
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    agg = {}
    for chain in bundle.get('chains', []):
        for ip in chain.get('victim_ips') or []:
            entry = agg.setdefault(ip, {'victim_ip': ip, 'attack_count': 0, 'tactics': [],
                                        'rank': 9, 'first_seen': None, 'last_seen': None})
            entry['attack_count'] += 1
            entry['rank'] = min(entry['rank'], order.get(chain.get('severity'), 9))
            first_seen, last_seen = chain.get('first_seen'), chain.get('last_seen')
            if first_seen and (not entry['first_seen'] or first_seen < entry['first_seen']):
                entry['first_seen'] = first_seen
            if last_seen and (not entry['last_seen'] or last_seen > entry['last_seen']):
                entry['last_seen'] = last_seen
            for stage in chain.get('stages') or []:
                tactic = str(stage.get('tactic') or '')
                if tactic and tactic not in entry['tactics']:
                    entry['tactics'].append(tactic)
    rank_to_sev = {rank: sev for sev, rank in order.items()}
    rows = sorted(agg.values(), key=lambda e: (-e['attack_count'], e['victim_ip']))[:10]
    for entry in rows:
        entry['max_severity'] = rank_to_sev.get(entry.pop('rank'), 'info')
        entry['tactics'] = entry['tactics'][:6]
    return rows


def _build_pdf_report(task) -> bytes:
    """结构化中文风险报告：执行摘要 → 统计 → 重点攻击链 → 处置建议 → 证据附录。"""
    global PDF_FONT_NAME
    regular = Path(os.getenv('NETGUARD_PDF_FONT', r'C:\Windows\Fonts\msyh.ttc'))
    bold = Path(os.getenv('NETGUARD_PDF_FONT_BOLD', r'C:\Windows\Fonts\msyhbd.ttc'))
    if regular.is_file():
        PDF_FONT_NAME = 'NetGuardCJK'
        pdfmetrics.registerFont(TTFont('NetGuardCJK', str(regular), subfontIndex=0))
        pdfmetrics.registerFont(TTFont('NetGuardCJK-Bold', str(bold if bold.is_file() else regular), subfontIndex=0))
        family = ('NetGuardCJK', 'NetGuardCJK-Bold')
    else:
        PDF_FONT_NAME = 'STSong-Light'
        pdfmetrics.registerFont(UnicodeCIDFont('STSong-Light'))
        family = ('STSong-Light', 'STSong-Light')
    from reportlab.pdfbase.pdfmetrics import registerFontFamily
    registerFontFamily(PDF_FONT_NAME, normal=family[0], bold=family[1],
                       italic=family[0], boldItalic=family[1])
    st = _pdf_styles()
    bundle = task.get('bundle', {})
    stats = summary(bundle)
    alerts = task.get('alerts', [])
    chains = bundle.get('chains', [])
    metrics = bundle.get('metrics', {})
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, topMargin=16*mm, bottomMargin=14*mm,
                            leftMargin=14*mm, rightMargin=14*mm, title='NetGuard 风险事件报告')

    def footer(canvas_obj, _doc):
        canvas_obj.saveState()
        canvas_obj.setFont(PDF_FONT_NAME, 8)
        canvas_obj.setFillColor(colors.HexColor('#9ca3af'))
        canvas_obj.drawString(14*mm, 8*mm, 'NetGuard 网络安全态势智能感知平台 · 机密')
        canvas_obj.drawRightString(A4[0]-14*mm, 8*mm, f'第 {canvas_obj.getPageNumber()} 页')
        canvas_obj.restoreState()

    def _fmt_duration(seconds):
        try:
            v = round(float(seconds))
        except (TypeError, ValueError):
            return '—'
        if v < 60: return f'{v} 秒'
        m = round(v / 60)
        if m < 60: return f'{m} 分钟'
        return f'{round(m / 60 * 10) / 10} 小时'

    story = []
    severity_cn = {'critical': '严重', 'high': '高危', 'medium': '中危', 'low': '低危', 'info': '提示'}
    story.append(Paragraph('网络安全态势 · 风险事件研判报告', st['title']))
    story.append(Paragraph(f"任务 ID：{task['task_id']}　|　输入文件：{task.get('filename','未知')}　|　"
                           f"生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}　|　"
                           f"研判模式：{'降级（规则引擎）' if task.get('degraded') else '智能（级联模型+云端研判）'}", st['sub']))
    story.append(Spacer(1, 6))

    # 一、执行摘要
    story.append(Paragraph('一、执行摘要', st['h1']))
    top_type = '、'.join(f"{k}({v}条)" for k, v in list(stats['attack_types'].items())[:3]) or '暂无'
    multistage = metrics.get('multistage_chains') or (bundle.get('report', {}).get('statistics', {}) or {}).get('multistage_chains') or 0
    chain_note = (f"，其中 {multistage} 条为跨多战术的多阶段链" if multistage
                  else "（本批多为单事件独立成链，链数接近事件数属正常）")
    fallback_summary = (f"本任务接入原始告警 {metrics.get('raw_count','—')} 条、可疑事件 "
                        f"{metrics.get('suspicious_count','—')} 条，确认攻击事件 {stats['alert_count']} 条，"
                        f"关联为 {stats['chain_count']} 条攻击链{chain_note}，涉及攻击者画像 "
                        f"{stats['attacker_count']} 个；其中高危及以上 {stats['high_count']} 条。"
                        f"主要威胁类型：{top_type}。")
    # 运营总结已在装配阶段按加权后的真实分布生成（含 cqsec），直接采用；缺失时用确定性兜底
    narrative = str(bundle.get('report', {}).get('summary') or '').strip() or fallback_summary
    story.append(Paragraph(_esc(narrative), st['body']))
    story.append(Spacer(1, 4))
    story.append(_pdf_table([
        [Paragraph('<b>原始告警</b>', st['cell']), Paragraph('<b>降噪后</b>', st['cell']),
         Paragraph('<b>可疑事件</b>', st['cell']), Paragraph('<b>攻击链</b>', st['cell']),
         Paragraph('<b>高危告警</b>', st['cell']), Paragraph('<b>M1+M2 全流程耗时</b>', st['cell'])],
        [Paragraph(str(metrics.get('raw_count','—')), st['cell']), Paragraph(str(metrics.get('denoised_count','—')), st['cell']),
         Paragraph(str(metrics.get('suspicious_count','—')), st['cell']), Paragraph(str(stats['chain_count']), st['cell']),
         Paragraph(str(stats['high_count']), st['cell']), Paragraph(_fmt_duration(metrics.get('duration_seconds')), st['cell'])],
    ], [26*mm]*6, st))
    story.append(Spacer(1, 4))

    # 运营效率：各阶段处理耗时（数字全部来自编排器实测计时，非模型生成）
    stage_items = [('M1 接入与降噪', 'm1_duration_seconds'), ('桥接证据转换', 'bridge_duration_seconds'),
                   ('M2 关联与研判', 'm2_process_duration_seconds'),
                   ('结果包装配', 'bundle_assembly_duration_seconds'), ('编排调度开销', 'orchestrator_overhead_seconds')]
    stage_rows = [[Paragraph('<b>处理阶段</b>', st['cell']), Paragraph('<b>耗时</b>', st['cell'])]]
    for name, key in stage_items:
        if metrics.get(key) is None:
            continue
        stage_rows.append([Paragraph(name, st['cell']), Paragraph(_fmt_duration(metrics.get(key)), st['cell'])])
    if len(stage_rows) > 1:
        story.append(Paragraph('各阶段处理耗时（端到端合计 ' + _fmt_duration(metrics.get('duration_seconds')) + '）', st['sub']))
        story.append(_pdf_table(stage_rows, [40*mm, 30*mm], st))
        story.append(Spacer(1, 4))

    # 二、告警统计
    story.append(Paragraph('二、告警统计', st['h1']))
    level_rows = [[Paragraph('<b>等级</b>', st['cell']), Paragraph('<b>数量</b>', st['cell']), Paragraph('<b>占比</b>', st['cell'])]]
    for level in ('critical', 'high', 'medium', 'low', 'info'):
        count = stats['severity_counts'].get(level, 0)
        share = f"{count / stats['alert_count'] * 100:.1f}%" if stats['alert_count'] else '—'
        level_rows.append([Paragraph(_esc(f"{severity_cn[level]}（{level}）"), st['cell']), str(count), share])
    story.append(_pdf_table(level_rows, [40*mm, 30*mm, 30*mm], st))
    story.append(Spacer(1, 4))
    type_rows = [[Paragraph('<b>攻击类型</b>', st['cell']), Paragraph('<b>数量</b>', st['cell'])]]
    for name, count in list(stats['attack_types'].items())[:10]:
        type_rows.append([Paragraph(_esc(name), st['cell']), str(count)])
    story.append(_pdf_table(type_rows, [70*mm, 30*mm], st))

    # 降噪漏斗（数据质量）：一行五列表 + 明细注脚；旧结果包无 quality 块时整段跳过
    quality = metrics.get('quality') or {}
    filtered = quality.get('filtered') or {}
    funnel_filters = [('空行', filtered.get('empty')), ('无意义行', filtered.get('meaningless')),
                      ('重复', filtered.get('duplicate')), ('白名单', filtered.get('whitelist')),
                      ('坏行', filtered.get('parse_error'))]
    if metrics.get('raw_count') is not None and all(v is not None for _, v in funnel_filters):
        filtered_total = sum(int(v or 0) for _, v in funnel_filters)
        ingested = int(metrics['raw_count']) - filtered_total
        story.append(Spacer(1, 4))
        story.append(Paragraph('<b>降噪漏斗（数据质量）</b>', st['body']))
        story.append(_pdf_table([
            [Paragraph('<b>原始接入</b>', st['cell']), Paragraph('<b>五级过滤</b>', st['cell']),
             Paragraph('<b>入库会话</b>', st['cell']), Paragraph('<b>可疑事件</b>', st['cell']),
             Paragraph('<b>确认告警</b>', st['cell'])],
            [Paragraph(str(metrics['raw_count']), st['cell']), Paragraph(str(filtered_total), st['cell']),
             Paragraph(str(ingested), st['cell']), Paragraph(str(metrics.get('suspicious_count', '—')), st['cell']),
             Paragraph(str(stats['alert_count']), st['cell'])],
        ], [26*mm, 24*mm, 26*mm, 26*mm, 26*mm], st))
        story.append(Paragraph(_esc('五级明细：' + ' · '.join(f'{name} {int(v or 0)}' for name, v in funnel_filters)), st['sub']))
        parse_errors = quality.get('parse_errors') or {}
        samples = parse_errors.get('samples') or []
        if samples:
            first = samples[0]
            story.append(Paragraph(_esc(f"坏行示例：第 {first.get('row', '?')} 行 {str(first.get('error') or '')[:60]}"
                                         f"（共 {parse_errors.get('total', len(samples))} 条，明细见平台）"), st['sub']))

    # 三、重点攻击链（Top 5，按等级与风险分）
    story.append(Paragraph('三、重点攻击链（Top 5）', st['h1']))
    order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
    for chain in sorted(chains, key=lambda c: (-(len(c.get('stages') or []) > 1), order.get(c.get('severity'), 9),
                                                -((c.get('confidence_card') or {}).get('score') or 0)))[:5]:
        card = chain.get('confidence_card') or {}
        # 注意：_esc 会转义全部输入，<b> 标记必须在拼接层给出，只对动态值转义
        head = Paragraph(
            f"<b>{_esc(chain.get('chain_id'))}</b> | 等级：<b>{_esc(severity_cn.get(chain.get('severity'), chain.get('severity')))}</b>"
            f" | 风险分：{_esc(card.get('score','—'))}/100 | 攻击源：{_esc('、'.join(chain.get('attacker_ips') or ['—']))}"
            f" | 受害资产：{_esc('、'.join(chain.get('victim_ips') or ['—']))}", st['body'])
        story.append(head)
        rows = [[Paragraph(f"<b>{i+1}</b>", st['cell']),
                 Paragraph(_esc(_att_cn(s.get('tactic',''))), st['cell']),
                 Paragraph(_esc(_att_cn(s.get('technique',''))), st['cell']),
                 Paragraph(f"{len(s.get('evidence_event_ids',[]))} 条", st['cell']),
                 Paragraph(_esc(_time_cn((s.get('time_range') or ['',''])[0]) + ' ~ ' + _time_cn((s.get('time_range') or ['',''])[-1])), st['cell'])]
                for i, s in enumerate(chain.get('stages', [])[:8])]
        if rows:
            story.append(_pdf_table([[Paragraph(f'<b>{x}</b>', st['cell']) for x in ('阶段','战术 (Tactic)','技术 (Technique)','证据','时间范围')]] + rows,
                                    [12*mm, 42*mm, 62*mm, 16*mm, 42*mm], st))
        if card.get('summary'):
            story.append(Paragraph('置信度：' + str(card['summary']), st['body']))
        story.append(Spacer(1, 5))

    # 四、攻击者画像（Top 8，按攻击次数）
    story.append(Paragraph('四、攻击者画像（Top 8）', st['h1']))
    profiles = sorted(bundle.get('profiles', []),
                      key=lambda p: -(p.get('attack_count') or 0))[:8]
    if profiles:
        sev_cn_map = severity_cn
        profile_rows = [[Paragraph('<b>攻击源</b>', st['cell']), Paragraph('<b>攻击次数</b>', st['cell']),
                         Paragraph('<b>最高等级</b>', st['cell']), Paragraph('<b>关联攻击链</b>', st['cell']),
                         Paragraph('<b>主要技术</b>', st['cell']), Paragraph('<b>目标资产</b>', st['cell'])]]
        for p in profiles:
            profile_rows.append([
                Paragraph(_esc('、'.join(p.get('attacker_ips') or [p.get('profile_id') or '—'])), st['cell']),
                str(p.get('attack_count', '—')),
                Paragraph(_esc(sev_cn_map.get(p.get('max_severity'), p.get('max_severity') or '—')), st['cell']),
                str(len(p.get('chain_ids') or [])),
                Paragraph(_esc('、'.join((p.get('techniques') or [])[:5])), st['cell']),
                str(len(p.get('target_assets') or [])),
            ])
        story.append(_pdf_table(profile_rows, [30*mm, 18*mm, 18*mm, 20*mm, 62*mm, 16*mm], st))
        top = profiles[:3]
        for p in top:
            story.append(Paragraph(_esc('· ' + ('、'.join(p.get('attacker_ips') or ['?'])) + '：' + _profile_cn(p)), st['body']))
    else:
        story.append(Paragraph('暂无攻击者画像。', st['body']))
    story.append(Spacer(1, 4))

    # 五、高风险资产（双榜单：受高威胁攻击 + 被多次攻击；assemble 一次算好旗标，
    # critical/high 是硬指针强制在榜——整体分数低时也不能漏掉被打进高危行为的资产）
    story.append(Paragraph('五、高风险资产', st['h1']))
    victim_rows = _victim_top(bundle)
    ranked = [v for v in victim_rows if 'threat_score' in v] if victim_rows else []

    def _asset_table(rows, score_key, score_label):
        tbl = [[Paragraph('<b>资产</b>', st['cell']), Paragraph('<b>命中告警</b>', st['cell']),
                Paragraph('<b>关联链</b>', st['cell']), Paragraph('<b>最严等级</b>', st['cell']),
                Paragraph(f'<b>{_esc(score_label)}</b>', st['cell']), Paragraph('<b>主要战术</b>', st['cell'])]]
        for v in rows:
            tactics = '、'.join(_att_cn(t).split('（')[0] for t in (v.get('tactics') or [])[:3])
            tbl.append([
                Paragraph(_esc(v.get('victim_ip') or '—'), st['cell']),
                Paragraph(str(v.get('alert_count', '—')), st['cell']),
                Paragraph(str(v.get('chain_count', '—')), st['cell']),
                Paragraph(_esc(severity_cn.get(v.get('max_severity'), v.get('max_severity') or '—')), st['cell']),
                Paragraph(_esc(v.get(score_key, '—')), st['cell']),
                Paragraph(_esc(tactics or '—'), st['cell']),
            ])
        return _pdf_table(tbl, [32*mm, 16*mm, 13*mm, 17*mm, 20*mm, 34*mm], st)

    if ranked:
        threat_rows = [v for v in victim_rows if v.get('in_threat_ranking')][:8]
        freq_rows = [v for v in victim_rows if v.get('in_freq_ranking')][:8]
        if threat_rows:
            story.append(Paragraph('受高威胁攻击的资产（最严等级 critical/high 强制在榜；其余按威胁指数相对线补足）', st['sub']))
            story.append(_asset_table(threat_rows, 'threat_score', '威胁指数'))
            story.append(Spacer(1, 3))
        if freq_rows:
            story.append(Paragraph('被多次攻击的资产（按命中告警数的对数指数，榜一恒为 100）', st['sub']))
            story.append(_asset_table(freq_rows, 'freq_score', '频次指数'))
    elif victim_rows:
        vtable = [[Paragraph('<b>资产</b>', st['cell']), Paragraph('<b>被攻击次数</b>', st['cell']),
                   Paragraph('<b>最高等级</b>', st['cell']), Paragraph('<b>主要战术</b>', st['cell']),
                   Paragraph('<b>首次 / 最近被攻击</b>', st['cell'])]]
        for v in victim_rows[:10]:
            tactics = '、'.join(_att_cn(t).split('（')[0] for t in (v.get('tactics') or [])[:4])
            vtable.append([
                Paragraph(_esc(v.get('victim_ip') or '—'), st['cell']),
                Paragraph(str(v.get('attack_count', '—')), st['cell']),
                Paragraph(_esc(severity_cn.get(v.get('max_severity'), v.get('max_severity') or '—')), st['cell']),
                Paragraph(_esc(tactics or '—'), st['cell']),
                Paragraph(_esc(_time_cn(v.get('first_seen') or '—') + ' ~ ' + _time_cn(v.get('last_seen') or '—')), st['cell']),
            ])
        story.append(_pdf_table(vtable, [32*mm, 24*mm, 18*mm, 42*mm, 40*mm], st))
    else:
        story.append(Paragraph('暂无受攻击资产记录。', st['body']))
    story.append(Spacer(1, 4))

    # 六、处置建议
    story.append(Paragraph('六、处置建议', st['h1']))
    source_cn = {'rule_based': '规则/证据', 'knowledge_base': '知识库', 'llm_generated': '模型生成', 'analyst_verified': '人工确认'}
    priority_cn = {'critical': '立即', 'high': '高', 'medium': '常规', 'low': '观察', 'info': '参考'}
    actions = bundle.get('report', {}).get('recommended_actions', [])
    if actions:
        action_rows = [[Paragraph('<b>#</b>', st['cell']), Paragraph('<b>处置建议</b>', st['cell']), Paragraph('<b>优先级/来源</b>', st['cell'])]]
        for i, action in enumerate(actions[:12], 1):
            code = next((t for t in (action.get('related_techniques') or []) if t in ADVICE_CN), None)
            if code:
                zh_title, zh_text = ADVICE_CN[code]
                cell = f'<b>{_esc(zh_title)}</b>：{_esc(zh_text)}'
            else:  # 无匹配技术的动态建议：保留原文并标注技术
                cell = f'<b>{_esc(action.get("title") or "")}</b>：{_esc(redact(str(action.get("text") or "")))}'
            action_rows.append([str(i), Paragraph(cell, st['cell']),
                                Paragraph(_esc((priority_cn.get(action.get('priority')) or action.get('priority') or '—') + ' / ' + source_cn.get(action.get('source'), action.get('source') or '—')), st['cell'])])
        story.append(_pdf_table(action_rows, [10*mm, 118*mm, 28*mm], st))
    else:
        story.append(Paragraph('暂无结构化处置建议。', st['body']))

    # 七、证据附录（前 20 条，已脱敏）
    story.append(Paragraph('七、证据附录（前 20 条，已脱敏）', st['h1']))
    evidence = (bundle.get('evidence') or [])[:20]
    if evidence:
        evidence_rows = [[Paragraph('<b>事件 ID</b>', st['cell']), Paragraph('<b>摘要</b>', st['cell'])]]
        for item in evidence:
            evidence_rows.append([Paragraph(_esc(str(item.get('event_id'))[:20]), st['cell']),
                                  Paragraph(_esc(redact(str(item.get('summary') or ''))[:150]), st['cell'])])
        story.append(_pdf_table(evidence_rows, [42*mm, 122*mm], st))
        story.append(Paragraph(f'（完整证据共 {len(bundle.get("evidence") or [])} 条，见 JSON 报告附件）', st['sub']))
    else:
        story.append(Paragraph('暂无证据记录。', st['body']))

    # 八、方法与版本
    story.append(Paragraph('八、方法与版本', st['h1']))
    versions = bundle.get('versions', {})
    story.append(Paragraph(_esc(
        '研判链路：数据接入与降噪（规则 ' + str(versions.get('rule_version', '—'))
        + '，含级联语义研判）→ 证据契约转换 → 攻击关联与风险研判（模型 '
        + str(versions.get('model_version', '—')) + '，提示词 '
        + str(versions.get('prompt_version', '—')) + '，阈值 '
        + str(versions.get('threshold_version', '—')) + '）→ 结果包校验（AttackChainBundle.v1）。'
        + ('本批次以规则引擎降级产出，LLM 未参与研判。' if task.get('degraded') else '本批次由级联模型与规则引擎联合研判产出。')
        + ' 本报告由 NetGuard 自动化引擎生成，所有数字与页面统计同源；证据均已脱敏，仅供内部处置参考，不构成法律取证结论。'), st['body']))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()

@app.get('/api/v1/intel/lookup')
def intel_lookup(q: str = '', type: str = 'auto'):
    """威胁情报：本地(瞬出)→在线地理/运营商(免key)→外部信誉库(有key才查)，分阶段返回。"""
    from intel_lookup import lookup as _lookup
    if not q.strip():
        raise HTTPException(400, '缺少查询内容 q')
    bundle = None
    try:
        current = next((t for t in tasks.values() if t.get('bundle')), None)
        bundle = current.get('bundle') if current else None
    except Exception:
        bundle = None
    audit('intel.lookup', '', redact(q[:100]))
    return _lookup(q, bundle)


@app.get('/api/v1/intel/deep')
def intel_deep(q: str = ''):
    """AI 联合研判（按需调用，强节流+缓存）。"""
    if not q.strip():
        raise HTTPException(400, '缺少查询内容 q')
    if len(q) > 200:
        raise HTTPException(400, '查询内容不能超过 200 个字符')
    try:
        from intel_lookup import deep_analysis
        bundle = None
        current = next((t for t in tasks.values() if t.get('bundle')), None)
        bundle = dict(current.get('bundle') or {}) if current else None
        if bundle is not None:
            bundle.setdefault('task_id', current.get('task_id') or current.get('id') or '')
        audit('intel.deep', '', redact(q[:100]))
        return deep_analysis(q.strip(), bundle)
    except Exception as exc:
        try:
            audit('intel.deep.error', '', type(exc).__name__)
        except Exception:
            pass
        return {'ok': False, 'source': '情报服务', 'note': 'AI 联合研判暂不可用；本地与在线查询结果仍可查看，请稍后重试。'}


@app.post('/api/v1/tasks/{task_id}/investigate')
def investigate(task_id: str):
    """一键自动调查：以 SSE 轨迹流式展示'载入→统计→逐链调查→反幻觉校验→结论'。"""
    task = task_for(task_id)
    if task['status'] != 'completed':
        raise HTTPException(409, '请等待任务完成')
    bundle = task.get('bundle', {})
    severities = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}

    async def stream():
        stats = summary(bundle)
        yield event('step', {'phase': 'load', 'title': '载入结果包', 'message':
                   f"任务 {task_id}：{stats['alert_count']} 条告警 / {stats['chain_count']} 条攻击链",
                   'detail': {k: stats.get(k) for k in ('alert_count', 'chain_count', 'attacker_count', 'high_count')}})
        await asyncio.sleep(0.15)
        yield event('step', {'phase': 'intel', 'title': '威胁情报富化', 'message':
                   '等级分布 ' + '，'.join(f'{k} {v}' for k, v in stats['severity_counts'].items()) +
                   '；主要类型 ' + '，'.join(f'{k} {v}' for k, v in list(stats['attack_types'].items())[:4]),
                   'detail': {'attack_types': stats['attack_types'], 'severity_counts': stats['severity_counts']}})
        await asyncio.sleep(0.15)
        chains = sorted(bundle.get('chains', []),
                        key=lambda c: (-(len(c.get('stages') or []) > 1), severities.get(c.get('severity'), 9),
                                       -((c.get('confidence_card') or {}).get('score') or 0)))
        top = chains[:5]
        hallucinated = 0
        for index, chain in enumerate(top, 1):
            card = chain.get('confidence_card') or {}
            validation = card.get('evidence_validation') or {}
            if validation.get('hallucination_detected'):
                hallucinated += 1
            yield event('step', {'phase': 'chain', 'title': f'调查攻击链 {index}/{len(top)}',
                       'message': f"{chain['chain_id']} [{chain.get('severity')}] "
                                  f"{len(chain.get('stages', []))} 阶段 / 风险分 {card.get('score', '?')}",
                       'detail': {
                           'chain_id': chain['chain_id'],
                           'severity': chain.get('severity'),
                           'stages': [{'tactic': s.get('tactic'), 'technique': s.get('technique'),
                                       'narrative': (s.get('narrative') or '')[:120],
                                       'evidence': len(s.get('evidence_event_ids', []))}
                                      for s in chain.get('stages', [])],
                           'attacker_ips': chain.get('attacker_ips', []),
                           'victim_ips': chain.get('victim_ips', []),
                           'confidence_card': card,
                       }})
            await asyncio.sleep(0.15)
        yield event('step', {'phase': 'validation', 'title': '反幻觉证据校验', 'message':
                   f"抽查 Top{len(top)} 攻击链：证据引用全部可回溯" + (f"；发现 {hallucinated} 条含幻觉扣分" if hallucinated else "，未发现幻觉"),
                   'detail': {'checked': len(top), 'hallucination': hallucinated}})
        await asyncio.sleep(0.15)
        yield event('done', {'chains': len(bundle.get('chains', [])), 'investigated': len(top),
                             'degraded': bool(bundle.get('degraded')),
                             'summary': f"已完成 {len(top)} 条高优先级攻击链的自动调查，共 {stats['alert_count']} 条告警、"
                                        f"{stats['chain_count']} 条链。多阶段链优先，其余按风险等级和评分排序。"})
    return StreamingResponse(stream(), media_type='text/event-stream', headers={'Cache-Control': 'no-cache'})


@app.post('/api/v1/admin/reset')
def admin_reset():
    """演示重置：清空任务/文件状态与工作区产物，便于反复验收。有任务运行中时拒绝。"""
    running = [t['task_id'] for t in tasks.values() if t.get('status') in ('queued', 'running')]
    if running:
        raise HTTPException(409, '有任务正在运行，无法重置：' + ','.join(running[:5]))
    import shutil
    ws = WORKSPACE.root
    cleared = []
    for sub in ['m3/READY', 'm3/STAGING', 'm1/STATUS', 'm1/running', 'm1/failed', 'm1/manifests',
                '04_m2_inbox', '05_m2_output', '06_status/m2', 'm2/READY', 'bridge', 'orchestrator']:
        target = Path(ws) / sub
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            target.mkdir(parents=True, exist_ok=True)
            cleared.append(sub)
    keep_incoming = Path(ws) / 'incoming'
    for stale in list(keep_incoming.glob('*')):
        try:
            stale.unlink()
            cleared.append('incoming/' + stale.name)
        except OSError:
            pass
    tasks.clear()
    files.clear()
    save_state()
    audit('admin.reset', '', json.dumps({'cleared': cleared[:10], 'count': len(cleared)}))
    return {'ok': True, 'cleared_dirs': len(cleared)}


@app.get('/api/v1/tasks/{task_id}/bundle')
def get_bundle(task_id: str):
    task = task_for(task_id)
    return task.get('bundle',{})

@app.post('/api/v1/tasks/{task_id}/view-alert/{alert_id}')
def view_alert(task_id: str, alert_id: str):
    task = task_for(task_id)
    if not any(a['alert_id']==alert_id for a in task['alerts']):
        raise HTTPException(404,'告警不存在')
    audit('alert.view',task_id,alert_id)
    with sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS alert_reads (task_id TEXT, alert_id TEXT, PRIMARY KEY(task_id,alert_id))')
        db.execute('INSERT OR IGNORE INTO alert_reads VALUES (?,?)', (task_id,alert_id))
    return {'ok':True}

@app.get('/api/v1/read-alerts')
def read_alerts():
    with sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS alert_reads (task_id TEXT, alert_id TEXT, PRIMARY KEY(task_id,alert_id))')
        return [{'task_id':r[0], 'alert_id':r[1]} for r in db.execute('SELECT task_id,alert_id FROM alert_reads')]

@app.get('/api/v1/tasks/{task_id}/audit')
def task_audit(task_id: str):
    task_for(task_id)
    with sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS audit (at TEXT, action TEXT, task_id TEXT, detail TEXT)')
        return [dict(zip(['at','action','detail'], r)) for r in db.execute('SELECT at,action,detail FROM audit WHERE task_id=? ORDER BY at DESC LIMIT 100', (task_id,))]

@app.get('/api/v1/tasks/{task_id}/chat-history')
def chat_history(task_id: str):
    task_for(task_id)
    with sqlite3.connect(STATE) as db:
        db.execute('CREATE TABLE IF NOT EXISTS chat_history (task_id TEXT, at TEXT, question TEXT, answer TEXT, citations TEXT)')
        return [dict(zip(['at','question','answer','citations'], r)) for r in db.execute('SELECT at,question,answer,citations FROM chat_history WHERE task_id=? ORDER BY at DESC LIMIT 50', (task_id,))][::-1]

@app.get('/health')
def health():
    return {'status':'ok', 'mode':'shared_files', 'llm':'configured' if os.getenv('NETGUARD_LLM_ENABLED') == '1' else 'disabled'}

@app.get('/')
def index():
    return FileResponse(ROOT / 'index.html')

@app.get('/{asset}')
def static(asset: str):
    if asset not in {'app.js', 'workflow.js', 'styles.css', 'm3-ui.js', 'm3-ext.js'}:
        raise HTTPException(404)
    return FileResponse(ROOT / asset)
