"""单事件研判报告（cqsec 能力②激活）：行构建不虚构字段 / 回退四要素同构 / 端点回退+缓存。

cqsec 服务在测试中不可达：LLM 开关关闭时端点必须走确定性汇总且来源诚实标注。
运行:  cd m3 && ../.venv/Scripts/python.exe -m pytest test_event_report.py -q
"""
import os
import tempfile
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix='netguard_evreport_')
os.environ.setdefault('NETGUARD_DATA_DIR', str(Path(_TMP) / 'data'))
os.environ.setdefault('NETGUARD_WORKSPACE', str(Path(_TMP) / 'shared'))
os.environ['NETGUARD_LLM_ENABLED'] = '0'

from server import (  # noqa: E402  环境变量必须在 import server 前就位
    _deterministic_event_report, _event_report_lines, app)
from fastapi.testclient import TestClient  # noqa: E402

EVIDENCE = [
    {'event_id': 'ev-1', 'timestamp': '2025-10-21T00:00:00+00:00',
     'url_path': "/api/login?u=admin' OR 1=1--&password=secret123",
     'attack_type': 'SQL注入攻击',
     'summary': "2025-10-21T00:00:00 10.25.73.34 -> 10.60.33.18 /api/login?u=admin' OR 1=1-- 载荷:password=secret123 [SQL注入攻击]"},
    {'event_id': 'ev-2', 'timestamp': '2025-10-21T00:00:25+00:00',
     'url_path': '/api/login',
     'attack_type': 'SQL注入攻击',
     'summary': '2025-10-21T00:00:25 10.25.73.34 -> 10.60.33.18 /api/login 载荷:(空) [SQL注入攻击]'},
]
ALERT = {
    'alert_id': 'alert_1', 'task_id': 't1', 'chain_id': 'chain_1',
    'title': '疑似SQL注入攻击：10.25.73.34 → 10.60.33.18', 'severity': 'high',
    'signal_severity': 'high', 'confidence': 0.8,
    'attack_type': 'SQL注入攻击', 'technique': 'T1190 利用漏洞',
    'attacker_ips': ['10.25.73.34'], 'victim_ips': ['10.60.33.18'],
    'event_ids': ['ev-1', 'ev-2'],
    'risk_reason': 'highest-impact tactic: TA0001 (Initial Access)',
}
BUNDLE = {
    'chains': [{'chain_id': 'chain_1', 'severity': 'high',
                'confidence_card': {'score': 78,
                                    'rationale': ['命中 sql_injection 规则']},
                'stages': [
                    {'tactic': 'TA0001', 'technique': 'T1190', 'evidence_event_ids': ['ev-1']},
                ]}],
    'report': {'recommended_actions': [
        {'title': '修补被利用的对外服务', 'text': '立即修补受影响组件。',
         'priority': 'high', 'source': 'rule_based', 'related_techniques': ['T1190']},
    ]},
}


def test_lines_no_method_fabrication_and_redaction():
    lines = _event_report_lines(EVIDENCE, limit=8)
    assert len(lines) == 2
    # 行格式 时间|URL|载荷摘要→类型；证据索引没有 method 列，绝不虚构 "GET|"
    assert 'GET|' not in lines[0] and 'POST|' not in lines[0]
    assert lines[0].startswith('  10-21 00:00|')
    assert '→SQL注入攻击' in lines[0]
    # 尾部「 [标签]」剥离 + secret 脱敏
    assert '[SQL注入攻击]' not in lines[0]
    assert 'secret123' not in lines[0]
    # 上限 8 行
    assert len(_event_report_lines([dict(EVIDENCE[0]) for _ in range(20)], limit=8)) == 8


def test_deterministic_report_four_sections():
    text = _deterministic_event_report(ALERT, EVIDENCE, BUNDLE)
    for section in ('【事件概述】', '【攻击证据】', '【风险等级】', '【处置建议】'):
        assert section in text, section
    # 数字全部来自系统字段，不出现编造统计
    assert '关联证据 2 条' in text
    assert '风险分 78/100' in text
    assert '10.25.73.34 → 10.60.33.18' in text
    # 证据与建议文本脱敏
    assert 'secret123' not in text


def test_endpoint_falls_back_and_caches():
    os.environ['NETGUARD_LLM_ENABLED'] = '0'
    from server import tasks, _EVENT_REPORT_CACHE
    tasks['t1'] = {'task_id': 't1', 'status': 'completed', 'filename': 'x.csv',
                   'alerts': [ALERT], 'chains': BUNDLE['chains'],
                   'bundle': {**BUNDLE, 'evidence': EVIDENCE, 'metrics': {}, 'report': BUNDLE['report']}}
    _EVENT_REPORT_CACHE.clear()
    client = TestClient(app)
    resp = client.post('/api/v1/tasks/t1/alert/alert_1/event-report')
    assert resp.status_code == 200
    data = resp.json()
    # 测试进程 LLM 关闭 → 确定性来源（诚实标注，不假装模型生成过）
    assert data['source'] == 'deterministic'
    assert data['note'] == ''
    assert '【事件概述】' in data['report']
    resp2 = client.post('/api/v1/tasks/t1/alert/alert_1/event-report')
    assert resp2.json()['cached'] is True
    assert _EVENT_REPORT_CACHE[('t1', 'alert_1')]['report'] == data['report']
    # 清理，避免污染同进程其它测试
    tasks.pop('t1', None)
    _EVENT_REPORT_CACHE.clear()
