/* NetGuard 平台扩展 v2：态势总览改版（任务分析实时流/指标合并/总量展示）
   + 一键调查 / 置信度卡片 / 情报查询 / 重置遮罩。
   加载顺序在 m3-ui.js 之后；仅覆写全局函数，不改原文件。 */
(function () {
  'use strict';
  var API = '/api/v1';

  function el(tag, style, text, cls) {
    var node = document.createElement(tag);
    Object.assign(node.style, style || {});
    if (text) node.textContent = text;
    if (cls) node.className = cls;
    return node;
  }

  /* ---------------- 注入样式 ---------------- */
  var css = document.createElement('style');
  css.textContent = [
    '.analysis-panel{margin-bottom:10px}',
    '.analysis-bars{display:flex;gap:14px;margin:8px 0;flex-wrap:wrap}',
    '.analysis-bars .ab{flex:1;min-width:260px;font-size:12px;color:#475569}',
    '.analysis-bars .ab .bar{height:8px;background:#eef2f7;border-radius:4px;overflow:hidden;margin-top:4px}',
    '.analysis-bars .ab .bar i{display:block;height:100%;width:100%;background:var(--blue-strong);transform-origin:left center;transition:transform .4s}',
    '.analysis-log{font-family:Consolas,monospace;font-size:12px;line-height:1.9;color:#334155;',
    '  background:rgba(15,23,42,.04);border:1px solid #e5eaf1;border-radius:8px;padding:10px 12px;max-height:150px;overflow-y:auto;white-space:pre-wrap}',
    '.analysis-log .ok{color:#16a34a}.analysis-log .warn{color:#d97706}',
    '.ext-panel{position:fixed;inset:76px 18px auto auto;width:min(460px,calc(100vw - 36px));max-height:calc(100vh - 94px);overflow:auto;background:#fff;z-index:9998;border:0;border-radius:14px;box-shadow:0 14px 38px rgba(15,23,42,.18);padding:0;color:#17243a;font-size:13px}',
    '.ext-panel-head{position:sticky;top:0;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:15px 18px;background:#f7f9fd;border-bottom:1px solid #e5eaf2}',
    '.ext-panel-head b{font-size:15px;font-weight:650;letter-spacing:-.01em}.ext-panel-close{width:36px;height:36px;border:1px solid #dbe3ef;border-radius:8px;background:#fff;color:#43516a;font-size:20px;cursor:pointer}',
    '.ext-panel-close:hover{background:#eef3ff;color:#244db8}.ext-panel-close:focus-visible,.ext-panel button:focus-visible{outline:2px solid #315bd6;outline-offset:2px}',
    '.ext-panel-body{padding:16px 18px 20px;line-height:1.65;overflow-wrap:anywhere}.ext-panel-body>div{max-width:72ch}',
    '.tool-intro{color:#52627a;font-size:12px;line-height:1.65;margin:0 0 14px}.tool-section{padding:12px 0;border-bottom:1px solid #edf0f5}.tool-section:last-child{border-bottom:0}',
    '.tool-state{padding:11px 12px;border:1px solid #dfe6f1;border-radius:9px;background:#f7f9fd;color:#41516a}.tool-state[data-kind="error"]{background:#fff8f2;border-color:#f1d7bd;color:#8b4516}.tool-action{min-height:40px;border:1px solid #cbd7ec;border-radius:8px;padding:8px 13px;background:#f4f7ff;color:#2349a5;font:inherit;font-weight:600;cursor:pointer}.tool-action:hover:not(:disabled){background:#eaf0ff}.tool-action:disabled{cursor:wait;opacity:.7}',
    '.stat-chips{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 10px}',
    '.stat-chips .chip{flex:1;min-width:110px;background:#f6f8fc;border:1px solid #e5eaf1;border-radius:8px;padding:8px 10px;text-align:center}',
    '.stat-chips .chip b{display:block;font-size:17px;color:#1f2937}',
    '.stat-chips .chip small{color:#6b7280;font-size:11px}',
    '#reset-overlay{position:fixed;inset:0;background:rgba(15,23,42,.55);z-index:10000;display:none;',
    '  align-items:center;justify-content:center;flex-direction:column;gap:12px;color:#fff;font-size:15px}',
    '#reset-overlay .spin{width:42px;height:42px;border:4px solid rgba(255,255,255,.27);border-top-color:#fff;border-radius:50%;animation:extspin 1s linear infinite}',
    '@keyframes extspin{to{transform:rotate(360deg)}}'
  ].join('\n');
  document.head.appendChild(css);

  function panel(title, width) {
    var box = el('div', { display: 'none' }, null, 'ext-panel');
    if (width) box.style.width = width;
    box.setAttribute('role', 'region'); box.setAttribute('aria-label', title);
    var head = el('div', {}, null, 'ext-panel-head');
    head.appendChild(el('b', {}, title));
    var close = el('button', {}, null, 'ext-panel-close');
    close.innerHTML = '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>';
    close.setAttribute('aria-label', '关闭' + title);
    close.onclick = function () { box.style.display = 'none'; };
    head.appendChild(close);
    box.appendChild(head);
    var body = el('div', {}, null, 'ext-panel-body');
    box.appendChild(body);
    document.body.appendChild(box);
    return { box: box, body: body };
  }

  function fetchCurrentTask() {
    return fetch(API + '/tasks').then(function (r) { return r.json(); }).then(function (list) {
      var completed = list.filter(function (t) { return t.status === 'completed'; });
      completed.sort(function (a, b) { return (b.created_at || '').localeCompare(a.created_at || ''); });
      return completed[0] || list[0] || null;
    });
  }

  function parseApiResponse(response, label) {
    return response.text().then(function (text) {
      var data;
      try { data = JSON.parse(text || '{}'); }
      catch (e) {
        var status = response.status ? '（HTTP ' + response.status + '）' : '';
        throw new Error(label + '服务返回了无法识别的错误响应' + status + '。请重试；若持续出现，请重启本地 8001 服务并查看服务日志。');
      }
      if (!response.ok) throw new Error((data && (data.note || data.detail)) || (label + '请求失败（HTTP ' + response.status + '）'));
      return data;
    });
  }

  /* ---------------- 任务分析：实时进度面板 ---------------- */
  var analysisLogs = new Map();   // task_id -> [{text, cls}]
  function pushLog(taskId, line, cls) {
    var arr = analysisLogs.get(taskId) || [];
    for (var i = Math.max(0, arr.length - 4); i < arr.length; i++) {
      if (arr[i].text === line) { arr[i].cls = cls || arr[i].cls; return; }
    }
    arr.push({ text: line, cls: cls || '' });
    if (arr.length > 60) arr.shift();
    analysisLogs.set(taskId, arr);
  }

  function fmtDetail(module, s) {
    // 阶段消息（s.message）已含完整计数，这里不再重复拼接
    return '';
  }

  /* 实时计数行：把 n/11000、模型研判 x/y 做成醒目数字块 */
  function renderAnalysisCounts(task) {
    var box = document.getElementById('analysis-counts');
    if (!box) return;
    var pending = task && ['queued', 'running'].includes(task.status);
    if (!pending) { box.hidden = true; box.replaceChildren(); return; }
    box.hidden = false;
    box.replaceChildren();
    (task.module_statuses || []).forEach(function (s) {
      var d = s.detail || {};
      var big = '', small = (s.module === 'm1' ? '数据接入与降噪' : '攻击关联与研判');
      if (s.module === 'm1') {
        if (d.total) { big = (d.processed || 0) + ' / ' + d.total; small += ' · 数据过滤（条）'; }
        else if (d.processed) { big = d.processed + ' 条'; small += ' · 已处理'; }
        else if (d.l3_total) { big = (d.l3_done || 0) + ' / ' + d.l3_total; small += ' · 语义研判'; }
        else { big = s.progress + '%'; }
      } else {
        if (d.llm_total) { big = (d.llm_done || 0) + ' / ' + d.llm_total; small += ' · 模型研判（候选）'; }
        else if (d.candidates != null) { big = d.candidates + ' 个'; small += ' · 攻击链候选'; }
        else { big = s.progress + '%'; }
      }
      var chip = el('div', {}, null, 'count-chip');
      var b = el('b'); b.textContent = big; chip.appendChild(b);
      var sm = el('small'); sm.textContent = small; chip.appendChild(sm);
      box.appendChild(chip);
    });
  }

  function renderAnalysisPanel() {
    var bars = document.querySelector('#analysis-bars');
    var log = document.querySelector('#analysis-log');
    var stateChip = document.querySelector('#analysis-state');
    var fileLabel = document.querySelector('#analysis-file');
    if (!bars || !log) return;
    // 优先展示运行中的任务（实时流最有价值），其次当前选中，最后最新完成
    var running0 = (taskList || []).filter(function (t) { return ['queued', 'running'].includes(t.status); });
    var task = running0[0] || currentTask || (taskList || []).filter(function (t) { return t.status === 'completed'; })
      .sort(function (a, b) { return (b.created_at || '').localeCompare(a.created_at || ''); })[0] || null;
    if (!task) {
      stateChip.textContent = '空闲'; stateChip.className = 'status running';
      log.textContent = '暂无任务。点击「＋ 新建分析任务」上传文件开始分析。';
      bars.replaceChildren(); return;
    }
    fileLabel.textContent = (task.filename || task.task_id) + ' · ' + displayStage(task);
    var pending = ['queued', 'running'].includes(task.status);
    stateChip.textContent = task.status === 'completed' ? '分析完成' : task.status === 'failed' ? '分析失败' : pending ? (task.status === 'queued' ? '排队中' : '分析中') : '等待结果';
    stateChip.className = 'status ' + (task.status === 'completed' ? 'done' : task.status === 'failed' ? 'failed' : 'running');

    bars.replaceChildren();
    renderAnalysisCounts(task);
    (task.module_statuses || []).forEach(function (s) {
      var box = el('div', {}, null, 'ab');
      var label = el('div', {}, null);
      label.textContent = (s.module === 'm1' ? '数据接入与降噪' : '攻击关联与风险研判') + ' · ' + String(s.message || '').replace(/^M[12]\s*/, '') + '（' + (s.progress || 0) + '%）';
      var bar = el('div', {}, null, 'bar'); var fill = el('i'); fill.style.transform = 'scaleX(' + (s.progress || 0) / 100 + ')'; bar.appendChild(fill);
      box.appendChild(label); box.appendChild(bar); bars.appendChild(box);
      var moduleLabel = s.module === 'm1' ? '接入降噪' : '关联研判';
      var message = String(s.message || '').replace(/^M[12]\s*/, '');
      pushLog(task.task_id, '[' + moduleLabel + '] ' + message + '（' + (s.progress || 0) + '%）' + fmtDetail(s.module, s));
    });
    if (!(task.module_statuses || []).length && pending) pushLog(task.task_id, '[等待] 已创建任务，等待分析流水线接管…');
    if (task.status === 'completed') {
      var m = (task.bundle && task.bundle.metrics) || {};
      pushLog(task.task_id, '✓ 任务完成：原始 ' + (m.raw_count != null ? m.raw_count : '—') + ' 条 → 可疑 ' +
        (m.suspicious_count != null ? m.suspicious_count : '—') + ' 条 → 攻击链 ' +
        ((task.chains && task.chains.length) || 0) + ' 条（M1+M2 全流程耗时 ' + (m.duration_seconds != null ? fmtDuration(m.duration_seconds) : '—') + '）', 'ok');
    }
    if (task.status === 'failed') pushLog(task.task_id, '✗ 任务失败：' + (task.stage || '详见编排器日志'), 'warn');

    var arr = analysisLogs.get(task.task_id) || [];
    log.replaceChildren();
    arr.slice(-14).forEach(function (item) {
      var line = el('div'); if (item.cls) line.className = item.cls; line.textContent = item.text; log.appendChild(line);
    });
    log.scrollTop = log.scrollHeight;
  }

  /* ---------------- 指标 chips + 总量 ---------------- */
  function renderStatChips() {
    var chips = document.querySelector('#stat-chips');
    if (!chips) return;
    chips.replaceChildren();
    var totalAlerts = allAlerts().length;
    var highChains = 0, verified = 0, rawTotal = 0, suspTotal = 0, hasData = false;
    (taskList || []).forEach(function (t) {
      highChains += (t.chains || []).filter(function (c) { return ['high', 'critical'].includes(c.severity); }).length;
      if (t.status === 'completed') verified++;
      var m = t.bundle && t.bundle.metrics;
      if (m && m.raw_count != null) { hasData = true; rawTotal += Number(m.raw_count) || 0; suspTotal += Number(m.suspicious_count) || 0; }
    });
    [[totalAlerts, '告警总数'], [highChains, '高危攻击链'], [verified > 0 ? '已校验' : '等待结果', '文件结果校验'],
     [hasData ? rawTotal.toLocaleString() : '—', '接入原始数据（条）'], [hasData ? suspTotal.toLocaleString() : '—', '降噪后可疑（条）']]
      .forEach(function (pair) {
        var chip = el('div', {}, null, 'chip');
        var b = el('b'); b.textContent = String(pair[0]); chip.appendChild(b);
        var sm = el('small'); sm.textContent = pair[1]; chip.appendChild(sm);
        chips.appendChild(chip);
      });
    var hero = document.querySelector('.hero-row p');
    if (hero) hero.textContent = '共 ' + (taskList || []).length + ' 个任务 · 接入原始数据 ' + rawTotal.toLocaleString() +
      ' 条 · 研判确认告警 ' + totalAlerts + ' 条（图表统计全部任务）';
  }

  /* ---------------- 覆写：真实进度替换假打字机动画 ---------------- */
  window.renderThinkingStatus = function () { /* 已由任务分析实时面板取代 */ };

  var _baseRenderTask = window.renderTask;
  window.renderTask = function () {
    _baseRenderTask();
    try { renderAnalysisPanel(); renderStatChips(); moveOverviewFacts(); } catch (e) {
      var l = document.getElementById('analysis-log');
      if (l) l.textContent = '渲染异常：' + (e && e.message) + (e && e.stack ? '\n' + String(e.stack).slice(0, 300) : '');
    }
  };

  function moveOverviewFacts() {
    var facts = document.querySelector('.task-facts');
    var overview = document.querySelector('#overview');
    if (!facts || !overview) return;
    var anchor = overview.querySelector('.analysis-panel');
    if (anchor && facts.previousElementSibling !== anchor) {
      overview.insertBefore(facts, anchor.nextSibling);
    }
  }

  /* ---------------- 告警详情：加载态 + 轻量端点 ---------------- */
  var _baseOpenAlertDetail = window.openAlertDetail;
  window.openAlertDetail = async function (alert) {
    alertDialog.replaceChildren();
    var loading = element('p', '加载告警详情…', alertDialog);
    var close0 = element('button', '关闭', alertDialog, 'secondary-btn');
    close0.onclick = function () { alertDialog.close(); };
    if (!alertDialog.open) alertDialog.showModal();
    try {
      await _baseOpenAlertDetail(alert);
    } catch (e) { loading.textContent = '加载失败：' + e.message + '（可关闭后重试）'; }
  };

  /* ---------------- 结果包面板：证据懒加载 ---------------- */
  var _baseRenderBundle = window.renderBundle;
  window.renderBundle = function () {
    var task = currentTask;
    if (task && task.bundle && !task.bundle.evidence && !task.__evidenceLoading) {
      task.__evidenceLoading = true;
      api('/tasks/' + task.task_id + '/bundle').then(function (full) {
        if (full && full.evidence) task.bundle.evidence = full.evidence;
      }).catch(function () { }).finally(function () { task.__evidenceLoading = false; });
    }
    return _baseRenderBundle();
  };

  /* ---------------- 图例合计 ---------------- */
  var _baseRenderRiskPie = window.renderRiskPie;
  window.renderRiskPie = function (alerts, infoObservations) {
    _baseRenderRiskPie(alerts, infoObservations);
    var legend = document.querySelector('#risk-legend');
    if (legend && alerts && alerts.length) {
      var previousTotal = legend.querySelector('.risk-legend-total'); if (previousTotal) previousTotal.remove();
      legend.appendChild(el('div', { borderTop: '1px solid #e5eaf1', marginTop: '4px', paddingTop: '4px', fontWeight: '600' },
        '合计 ' + alerts.length + ' 条告警' + (infoObservations ? '；另有 ' + infoObservations + ' 个信息级观察（不计告警）' : ''), 'risk-legend-total'));
    }
  };

  /* ---------------- 一键自动调查 ---------------- */
  var invPanel = panel('一键自动调查（SSE 轨迹）');
  var invTip = el('div', { fontSize: '11px', color: '#94a3b8', marginBottom: '6px' },
    '自动调查高优先级攻击链：多阶段链优先，其余按等级与风险分排序；依次完成情报富化、路径还原、证据校验与处置结论。');
  invTip.className = 'tool-intro';
  function runInvestigate() {
    fetchCurrentTask().then(function (task) {
      if (!task) { alert('暂无任务，请先创建分析任务'); return; }
      invPanel.box.style.display = 'block';
      invPanel.body.replaceChildren();
      invPanel.body.appendChild(invTip);
      invPanel.body.appendChild(el('div', { color: '#64748b' }, '正在调查任务 ' + task.task_id.slice(0, 8) + '…'));
      fetch(API + '/tasks/' + task.task_id + '/investigate', { method: 'POST' }).then(function (resp) {
        if (!resp.ok || !resp.body) throw new Error('HTTP ' + resp.status + '：调查服务暂不可用，请稍后重试');
        invPanel.body.removeChild(invPanel.body.children[1]);
        var reader = resp.body.getReader(); var decoder = new TextDecoder(); var buffer = '';
        function renderStep(d) {
          var item = el('div', { margin: '6px 0' }, null, 'inv-step');
          var t = el('div', {}, null); t.style.fontWeight = '600'; t.textContent = (d.title || d.phase);
          item.appendChild(t);
          if (d.message) item.appendChild(el('div', { color: '#475569', whiteSpace: 'pre-wrap' }, d.message));
          if (d.detail && d.detail.stages) {
            d.detail.stages.forEach(function (s) {
              var tactic = window.attCn ? attCn(s.tactic).cn : (s.tactic || '');
              var technique = window.attCn ? attCn(s.technique).cn : (s.technique || '');
              item.appendChild(el('div', { color: '#64748b', marginLeft: '10px' },
                '· ' + tactic + ' / ' + technique + '（证据 ' + s.evidence + ' 条）'));
            });
            var card = d.detail.confidence_card || {};
            if (card.summary) item.appendChild(el('div', { marginLeft: '10px', color: '#b45309' }, '置信度：' + String(card.summary).replace(/LLM/g,'模型')));
          }
          invPanel.body.appendChild(item);
          invPanel.box.scrollTop = invPanel.box.scrollHeight;
        }
        function pump() {
          return reader.read().then(function (r) {
            if (r.done) return;
            buffer += decoder.decode(r.value, { stream: true });
            var frames = buffer.split('\n\n'); buffer = frames.pop();
            frames.forEach(function (frame) {
              var name = '', data = '';
              frame.split('\n').forEach(function (l) {
                if (l.indexOf('event:') === 0) name = l.slice(6).trim();
                if (l.indexOf('data:') === 0) data += l.slice(5).trim();
              });
              if (!data) return;
              try { var d = JSON.parse(data); } catch (e) { return; }
              if (name === 'step') renderStep(d);
              if (name === 'done') invPanel.body.appendChild(el('div', { marginTop: '8px', fontWeight: '600', color: '#16a34a' }, '✓ ' + (d.summary || '调查完成')));
            });
            return pump();
          });
        }
        return pump();
      }).catch(function (e) { invPanel.body.replaceChildren(); var error = el('div', {}, '调查失败：' + (e.message || e), 'tool-state'); error.dataset.kind = 'error'; invPanel.body.appendChild(error); });
    });
  }

  /* ---------------- 置信度卡片 ---------------- */
  var cardPanel = panel('证据链置信度卡片');
  var cardTip = el('div', { fontSize: '11px', color: '#94a3b8', marginBottom: '6px' },
    '每条攻击链的 8 因子评分、证据闭合校验与扣分项——说明风险结论为什么可信、哪些因素降低了置信度。');
  cardTip.className = 'tool-intro';
  function sevColor(sev) {
    return { critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#2563eb', info: '#64748b' }[sev] || '#64748b';
  }
  var FACTOR_CN = {
    tactic_severity: '战术严重度', evidence_strength: '证据强度', ioc: 'IOC 命中',
    asset_criticality: '资产重要性', rule_score: '规则评分', llm_confidence: '模型置信度',
    chain_length: '链长度', multi_stage: '多阶段'
  };
  function renderCard(chain) {
    var card = chain.confidence_card || {};
    var box = el('div', { border: '1px solid #e2e8f0', borderRadius: '8px', padding: '8px', margin: '8px 0' });
    box.appendChild(el('div', { fontWeight: '700' },
      chain.chain_id + '  [' + sevCN(chain.severity) + ']  风险分 ' + (card.score != null ? card.score : '?') + '/100'));
    if (card.summary) box.appendChild(el('div', { color: '#475569', margin: '4px 0' }, String(card.summary).replace(/LLM\s*/g,'模型')));
    (card.factors || []).forEach(function (f) {
      var row = el('div', { display: 'flex', alignItems: 'center', margin: '2px 0', fontSize: '12px' });
      var name = el('span', { width: '150px', color: '#334155' }, (FACTOR_CN[f.name] || f.name) + '（权重 ' + f.weight + '）');
      if (f.description) name.title = f.description;
      var bar = el('div', { flex: '1', height: '8px', background: '#f1f5f9', borderRadius: '4px', overflow: 'hidden', margin: '0 6px' });
      var fill = el('div', { height: '100%', width: Math.round((f.value || 0) * 100) + '%', background: sevColor(chain.severity) });
      bar.appendChild(fill);
      var val = el('span', { width: '44px', textAlign: 'right' }, (f.contribution != null ? f.contribution : f.value));
      row.appendChild(name); row.appendChild(bar); row.appendChild(val);
      box.appendChild(row);
    });
    (card.penalties || []).forEach(function (p) {
      box.appendChild(el('div', { color: '#dc2626', fontSize: '12px' }, '扣分项：' + String(p.reason||'').replace(/LLM/g,'模型') + (p.amount != null ? '（-' + p.amount + '）' : '')));
    });
    (card.rationale || []).slice(0, 3).forEach(function (r0) {
      var rationale=String(r0)
        .replace(/highest-impact tactic:\s*(TA\d{4})\s*\([^)]+\)/i,function(_,code){return '最高影响战术：'+(window.attCn?attCn(code).cn:code)+'（'+code+'）';})
        .replace(/highest-impact tactic:\s*/i,'最高影响战术：')
        .replace(/(\d+) independent evidence events support the chain/i,'$1 条独立证据支持本链')
        .replace(/(\d+) distinct ATT&CK tactics observed/i,'观测到 $1 类不同 ATT&CK 战术')
        .replace(/score ([\d.]+) -> medium \(threshold ([\d.]+)\)/i,'风险分 $1，达到中危阈值 $2');
      box.appendChild(el('div', { color: '#64748b', fontSize: '12px' }, '· ' + rationale));
    });
    var v = card.evidence_validation || {};
    var referenced = new Set((chain.stages || []).flatMap(function(s){ return s.evidence_event_ids || []; })).size;
    var validationText = v.valid
      ? '阶段证据引用 ' + referenced + ' 条，均可回溯'
      : '证据引用存在缺失，需人工复核';
    if (v.valid_evidence_count === 0 && referenced) validationText += '；模型未采用额外证据，风险分按规则链计算';
    box.appendChild(el('div', { fontSize: '12px', color: v.hallucination_detected ? '#dc2626' : '#16a34a' },
      '证据闭合校验：' + validationText + '；剔除阶段 ' + (v.dropped_stages || 0)));
    return box;
  }
  function showCards() {
    fetchCurrentTask().then(function (task) {
      if (!task) { alert('暂无已完成任务的结果包'); return; }
      // 列表接口的 bundle 已瘦身（不含 chains），卡片需要完整链数据，改取详情接口。
      return fetch(API + '/tasks/' + task.task_id).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status + '：无法读取任务结果'); return r.json(); });
    }).then(function (task) {
      if (!task || !task.bundle) { cardPanel.box.style.display = 'block'; cardPanel.body.replaceChildren(); cardPanel.body.appendChild(el('div', {}, '暂无已完成任务的结果包。请先完成一次分析，再查看置信度依据。', 'tool-state')); return; }
      cardPanel.box.style.display = 'block';
      cardPanel.body.replaceChildren();
      cardPanel.body.appendChild(cardTip);
      var severities = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      var chains = (task.chains || task.bundle.chains || []).slice().sort(function (a, b) {
        return (((b.stages || []).length > 1) - ((a.stages || []).length > 1)) ||
          (severities[a.severity] ?? 9) - (severities[b.severity] ?? 9) ||
          ((b.confidence_card || {}).score || 0) - ((a.confidence_card || {}).score || 0);
      }).slice(0, 10);
      if (!chains.length) cardPanel.body.appendChild(el('div', { color: '#64748b' }, '结果包中没有攻击链'));
      chains.forEach(function (c) { cardPanel.body.appendChild(renderCard(c)); });
    }).catch(function (e) { cardPanel.box.style.display = 'block'; cardPanel.body.replaceChildren(); var error = el('div', {}, '读取置信度卡片失败：' + (e.message || e), 'tool-state'); error.dataset.kind = 'error'; cardPanel.body.appendChild(error); });
  }

  /* ---------------- 威胁情报查询 ---------------- */
  var intelPanel = panel('威胁情报查询');
  function stageBadge(state) {
    var map = { done: ['✓ 完成', '#16a34a'], running: ['… 检索中', '#2563eb'], skipped: ['· 跳过', '#94a3b8'], failed: ['! 不可达', '#d97706'] };
    var v = map[state] || ['·', '#94a3b8'];
    var s = el('span', { fontSize: '11px', color: v[1], marginLeft: '6px' }, v[0]); return s;
  }
  function renderIntel(d) {
    intelPanel.body.replaceChildren();
    intelPanel.body.appendChild(el('div', { fontWeight: '700', marginBottom: '6px' },
      '查询对象：' + d.q + '　（类型：' + ({ ip: 'IP 地址', domain: '域名', attack: '攻击类型', cve: 'CVE 已知漏洞', technique: 'ATT&CK 技术' }[d.type] || '未知') + '）'));
    intelPanel.body.appendChild(el('div', { fontSize: '11.5px', color: '#64748b', marginBottom: '8px', lineHeight: '1.7' },
      '下面按“本地→在线→信誉库→AI”四层给出研判，逐层更权威：' +
      '「本地」＝设备内置离线库（地理位置 ip2region、恶意清单 IOC、攻击手法库，秒出、不联网）；' +
      '「在线」＝实时查 ip-api.com 取归属国家/运营商；「ASN＝运营商编号，ATT&CK＝国际通用攻击手法编号」；' +
      '「信誉库」＝联网查 AbuseIPDB/OTX（需你提供密钥才启用）；「AI」＝大模型综合研判。' +
      '任何一层拿不到结果都会如实说明，不编造。'));
    (d.stages || []).forEach(function (st) {
      var box = el('div', { border: '1px solid #e6ebf3', borderRadius: '8px', padding: '8px 10px', margin: '7px 0', fontSize: '12.5px' });
      var head = el('div', { display: 'flex', alignItems: 'center' });
      head.appendChild(el('b', {}, st.label)); head.appendChild(stageBadge(st.state));
      box.appendChild(head);
      var data = st.data || {};
      if (st.key === 'local') {
        var g = data.geo || {};
        if (g.region) box.appendChild(el('div', { color: '#475569', marginTop: '4px' },
          '地理(离线)：' + g.region + (g.in_china === true ? ' 境内' : g.in_china === false ? ' 境外' : '')));
        var m = data.malicious || {};
        if (m.hit !== undefined) box.appendChild(el('div', { color: m.hit ? '#dc2626' : '#16a34a' },
          m.hit ? '【恶意】命中本地 IOC 黑名单（' + (m.sources || []).join('、') + '）' : '本地 IOC 库未命中（不代表绝对安全）'));
        (m.detail || []).forEach(function (h) { box.appendChild(el('div', { color: '#64748b' }, '· ' + h.matched + '（' + h.source + '）')); });
        if (data.in_task && data.in_task.in_task) box.appendChild(el('div', { color: '#b45309' }, '⚠ 该指标出现在当前分析任务中'));
      } else if (st.key === 'online') {
        if (data.ok) {
          box.appendChild(el('div', { color: '#475569', marginTop: '4px' },
            '国家/地区：' + (data.country || '—') + (data.region ? ' · ' + data.region : '') + '　' + (data.in_china ? '【境内】' : '【境外】')));
          box.appendChild(el('div', { color: '#475569' }, '运营商/组织：' + (data.isp || '—') + (data.org && data.org !== data.isp ? ' / ' + data.org : '')));
          if (data.asn) box.appendChild(el('div', { color: '#475569' }, '自治系统编号(ASN)：' + data.asn));
          if (data.reverse) box.appendChild(el('div', { color: '#475569' }, '反向解析：' + data.reverse));
        } else box.appendChild(el('div', { color: '#d97706', marginTop: '4px' }, data.note || '在线源不可达（可能需代理，可在 .env 设 NETGUARD_INTEL_PROXY）'));
      } else if (st.key === 'reputation') {
        box.appendChild(el('div', { color: st.state === 'done' ? '#334155' : '#94a3b8', marginTop: '4px' }, data.note || ''));
        (data.detail || []).forEach(function (h) { box.appendChild(el('div', { color: '#64748b' }, '· [' + h.source + '] ' + h.matched)); });
        if (data.hit) box.appendChild(el('div', { color: '#dc2626', fontWeight: '600' }, '外部信誉库判定：恶意'));
      }
      intelPanel.body.appendChild(box);
    });
    // 攻击类型知识库
    var k = d.knowledge;
    if (k) {
      var kb = el('div', { border: '1px solid #e2e8f0', borderRadius: '8px', padding: '8px', marginTop: '6px' });
      if (k.title) kb.appendChild(el('div', { fontWeight: '700', fontSize: '13px' }, k.title));
      if (k.mitre) kb.appendChild(el('div', { fontWeight: '600' }, 'ATT&CK：' + k.mitre));
      if (k.vendor || k.product) kb.appendChild(el('div', { color: '#475569' }, '厂商/产品：' + [k.vendor, k.product].filter(Boolean).join(' / ')));
      if (k.platforms && k.platforms.length) kb.appendChild(el('div', { color: '#475569' }, '适用平台：' + k.platforms.join('、')));
      if (k.tactics && k.tactics.length) kb.appendChild(el('div', { color: '#475569' }, '关联战术：' + k.tactics.join('、')));
      if (k.intro) kb.appendChild(el('div', { margin: '4px 0' }, k.intro));
      if (k.signs) kb.appendChild(el('div', { color: '#475569' }, '特征：' + k.signs));
      if (k.mitigation) kb.appendChild(el('div', { color: '#475569' }, '处置：' + k.mitigation));
      if (k.date_added || k.due_date) kb.appendChild(el('div', { color: '#475569' }, 'CISA 收录/整改期限：' + (k.date_added || '—') + ' / ' + (k.due_date || '—')));
      if (k.ransomware) kb.appendChild(el('div', { color: '#475569' }, '勒索活动利用：' + k.ransomware));
      if (k.source) kb.appendChild(el('div', { color: '#64748b', fontSize: '11.5px', marginTop: '5px' }, '知识来源：' + k.source));
      if (k.url) { var sourceLink=el('a', { color: '#2563eb', fontSize: '11.5px' }, '查看官方技术条目'); sourceLink.href=k.url; sourceLink.target='_blank'; sourceLink.rel='noopener noreferrer'; kb.appendChild(sourceLink); }
      intelPanel.body.appendChild(kb);
    }
    // AI 深度分析默认随查询启动；服务端缓存和限流保护模型额度。
    if (d.type && d.type !== 'unknown') {
      var deepBox = el('div', { marginTop: '10px' });
      var btn = el('button', { border: '1px solid #cbd5e1', background: 'rgba(99,102,241,.1)', borderRadius: '7px', padding: '6px 12px', cursor: 'pointer', fontSize: '13px', minHeight: '36px' }, 'AI 正在自动综合研判…');
      var out = el('div', { marginTop: '8px', whiteSpace: 'pre-wrap', fontSize: '12.5px', color: '#334155' });
      function requestDeep(manualRetry) {
        btn.disabled = true; btn.textContent = manualRetry ? 'AI 正在重新研判…' : 'AI 正在自动综合研判…';
        out.textContent = '正在汇总本地与在线证据；本地查询结果可继续查看。';
        btn.setAttribute('aria-busy', 'true');
        fetch(API + '/intel/deep?q=' + encodeURIComponent(d.q)).then(function (r) { return parseApiResponse(r, 'AI 联合研判'); })
          .then(function (j) {
            out.className = '';
            out.removeAttribute('role');
            if (j.throttled) { out.textContent = j.note || '请求较频繁，请稍后再试。'; btn.disabled = false; btn.textContent = '稍后重试 AI 研判'; }
            else if (j.ok) { out.textContent = (j.cached ? '（缓存结果）\n' : '') + j.text; btn.disabled = false; btn.textContent = '重新 AI 研判'; }
            else { out.textContent = '研判未完成：' + (j.note || '模型服务暂不可用'); btn.disabled = false; btn.textContent = '重试 AI 研判'; }
          })
          .catch(function (e) {
            out.textContent = (e.message || 'AI 分析请求失败') + ' 本地查询结果仍可使用。';
            out.className = 'tool-state'; out.dataset.kind = 'error'; out.setAttribute('role', 'alert');
            btn.disabled = false; btn.textContent = '重试 AI 研判';
          })
          .finally(function () { btn.removeAttribute('aria-busy'); });
      }
      btn.onclick = function () { requestDeep(true); };
      deepBox.appendChild(btn); deepBox.appendChild(out);
      intelPanel.body.appendChild(deepBox);
      requestDeep(false);
    }
    if (d.note && d.type === 'unknown') intelPanel.body.appendChild(el('div', { color: '#64748b', marginTop: '6px' }, d.note));
  }
  function doLookup(q) {
    if (!q) return;
    intelPanel.box.style.display = 'block';
    intelPanel.body.replaceChildren(); intelPanel.body.appendChild(el('div', {}, '正在查询本地情报，并按可用性补充在线来源…', 'tool-state'));
    intelPanel.box.setAttribute('aria-busy', 'true');
    fetch(API + '/intel/lookup?q=' + encodeURIComponent(q)).then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status + '：查询服务暂不可用'); return r.json(); })
      .then(renderIntel)
      .catch(function (e) { intelPanel.body.replaceChildren(); var error = el('div', {}, '查询失败：' + (e.message || e) + '。可检查本地服务后重试。', 'tool-state'); error.dataset.kind = 'error'; intelPanel.body.appendChild(error); })
      .finally(function () { intelPanel.box.removeAttribute('aria-busy'); });
  }

  /* ---------------- 重置：全屏遮罩 ---------------- */
  var overlay = el('div', {}, null); overlay.id = 'reset-overlay';
  overlay.appendChild(el('div', {}, null, 'spin'));
  var overlayText = el('div', {}, '正在重置演示环境（清空任务/文件/工作区）…');
  overlay.appendChild(overlayText);
  document.body.appendChild(overlay);
  var resetInFlight = false;
  function resetDemo() {
    if (resetInFlight) return;
    resetInFlight = true;
    var resetButton = document.querySelector('.sidebar-reset');
    if (resetButton) {
      resetButton.disabled = true;
      resetButton.setAttribute('aria-busy', 'true');
      var label = resetButton.querySelector('span'); if (label) label.textContent = '正在重置…';
    }
    overlayText.textContent = '正在重置演示环境（清空任务/文件/工作区）…';
    overlay.style.display = 'flex';
    fetch(API + '/admin/reset', { method: 'POST' })
      .then(function (r) { return r.json().catch(function () { throw new Error('HTTP ' + r.status); }).then(function (d) { if (!r.ok) throw new Error(d.detail || ('HTTP ' + r.status)); return d; }); })
      .then(function (d) {
        if (d.ok) { overlayText.textContent = '已重置（清理 ' + d.cleared_dirs + ' 项），正在刷新…'; setTimeout(function () { location.reload(); }, 700); }
        else { throw new Error(d.detail || JSON.stringify(d)); }
      })
      .catch(function (e) {
        overlay.style.display = 'none'; resetInFlight = false;
        if (resetButton) { resetButton.disabled = false; resetButton.removeAttribute('aria-busy'); var label = resetButton.querySelector('span'); if (label) label.textContent = '重置演示环境'; }
        alert('重置失败：' + e.message);
      });
  }

  /* ---------------- 注入：AI 工具进工作台 / 重置进侧栏 / 实时计数行 ---------------- */
  var TOOL_ICONS = {
    zap: '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>',
    shield: '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    search: '<svg class="icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>'
  };
  function inject() {
    // ① AI 工具按钮与流程按钮同排（分析工作台右侧），替代原先悬浮的工具条；图标一律 SVG
    var tools = document.getElementById('ai-tools');
    if (tools) {
      function mkBtn(icon, text, tip, fn) {
        var b = el('button', {}, null, 'tool-btn');
        b.innerHTML = icon + ' ';
        b.appendChild(document.createTextNode(text));
        b.title = tip; b.onclick = fn; return b;
      }
      tools.appendChild(mkBtn(TOOL_ICONS.zap, '一键自动调查', '自动调查高优先级攻击链：多阶段链优先，其余按等级与风险分排序；依次完成情报富化、路径分析、证据校验和处置结论', runInvestigate));
      tools.appendChild(mkBtn(TOOL_ICONS.shield, '置信度卡片', '查看每条攻击链的 8 因子风险评分、证据闭合校验与扣分项，解释风险结论为什么可信', showCards));
      tools.appendChild(mkBtn(TOOL_ICONS.search, '威胁情报查询', '输入 IP / 域名 / 攻击类型：查询境内境外归属（离线 GeoIP）、是否恶意（本地 IOC 库）、攻击手法简介与处置建议', function () {
        intelPanel.box.style.display = 'block';
        if (!intelPanel.body.querySelector('input')) {
          intelPanel.body.replaceChildren();
          var row = el('div', { display: 'flex', gap: '6px', marginBottom: '8px' });
          var input = el('input', { flex: '1', border: '1px solid #cbd5e1', borderRadius: '6px', padding: '6px' });
          input.placeholder = '输入 IP / 域名 / 攻击类型（如 8.8.8.8、SQL注入攻击）';
          input.setAttribute('aria-label', '威胁情报查询对象');
          var go = el('button', {}, '查询', 'tool-action');
          go.onclick = function () { doLookup(input.value.trim()); };
          input.addEventListener('keydown', function (e) { if (e.key === 'Enter') doLookup(input.value.trim()); });
          row.appendChild(input); row.appendChild(go);
          intelPanel.body.appendChild(row);
          intelPanel.body.appendChild(el('div', { color: '#94a3b8', fontSize: '12px' },
            '本地数据源：ip2region / Spamhaus DROP / OpenPhish / OTX 订阅情报 / CISA KEV / MITRE ATT&CK；IP 外部信誉按需查询 AbuseIPDB 与 OTX，并缓存 15 分钟。'));
        }
      }));
    }
    // ② 重置演示入口移到侧栏底部（低调、危险色），点击后全屏遮罩阻断操作直到完成
    var sb = document.querySelector('.sidebar-bottom');
    if (sb) {
      var r = sb.querySelector('.sidebar-reset');
      if (!r) { r = el('button', {}, '↺ 重置演示环境', 'sidebar-reset'); sb.insertBefore(r, sb.firstChild); }
      r.title = '清空全部任务、文件与工作区产物，恢复初始演示状态（有任务运行时会被拒绝）';
      r.type = 'button';
      if (!r.dataset.resetBound) { r.addEventListener('click', resetDemo); r.dataset.resetBound = 'true'; }
    }
    // ③ 任务分析面板的实时计数行（数据过滤 n/总数、模型研判 x/y 等）
    var log = document.getElementById('analysis-log');
    if (log && !document.getElementById('analysis-counts')) {
      var counts = el('div', {}, null, 'analysis-counts');
      counts.hidden = true;
      log.parentNode.insertBefore(counts, log);
    }
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else { inject(); }
})();
