// Browser flow: upload -> task -> SSE -> results -> chat stream / report.
let currentTask = null, currentChain = null, taskAlerts = [], stream = null;
function displayStage(task) {
  if (task.status === 'completed') return '分析完成';
  return String(task.stage || '等待分析').replace(/（降级）|\(降级\)/g, '').replace(/等待 M1\/M2 文件结果/g, '等待分析流水线结果');
}
function displayAnswer(text) {
  const prefix = '【本地检索与统计回答，LLM 未启用或不可用】';
  const value = String(text || '');
  if (prefix.startsWith(value)) return '';
  return value.replace(prefix, '').replace('关联多条攻击链的画像（仅使用 M2 提供的关联）', '关联多条攻击链的画像').replaceAll('M2 未提供，不能仅凭等级解释原因', '暂无详细风险依据').trimStart();
}
const hour = new Date().getHours();
const greeting = hour < 5 ? '晚上好' : hour < 11 ? '早上好' : hour < 13 ? '中午好' : hour < 18 ? '下午好' : '晚上好';
const greetingNode = document.querySelector('#greeting');
if (greetingNode) greetingNode.textContent = greeting;
const main = document.querySelector('.main-content');
const banner = document.createElement('section');
banner.className = 'workflow-banner';
banner.innerHTML = '<div class="workbench-title"><b>分析工作台</b><small>当前任务的报告、调查与情报入口</small></div><div id="flow-status" role="status">请选择文件并创建任务</div><div class="banner-actions"><div class="chain-actions" id="flow-actions"><button id="show-results" disabled title="打开当前任务的执行摘要、风险分布和处置建议">打开风险报告</button><button id="ask-task" disabled title="用自然语言查询当前任务，例如“哪些资产应先处置”">智能问答</button><button id="report-json" disabled title="下载含证据引用和处理版本的机器可读归档">下载证据包 JSON</button><button id="report-pdf" disabled title="下载适合汇报和打印的中文风险报告">下载汇报版 PDF</button></div><div class="ai-tools" id="ai-tools"></div></div>';
main.insertBefore(banner, document.querySelector('.view'));
const statusBox = document.querySelector('#flow-status');
function flowStatus(text) { statusBox.textContent = text; }
async function api(path, options = {}) {
  const response = await fetch('/api/v1' + path, options);
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(typeof error.detail === 'string' ? error.detail : `请求失败 (${response.status})`);
  }
  return response.json();
}
function post(body) { return {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}; }
function enableResults(value) {
  for (const id of ['show-results','ask-task','report-json','report-pdf','send-chat']) document.getElementById(id).disabled = !value;
}
enableResults(false);
let taskList = [], selectionVersion = 0;
const readAlerts = new Set();
const alertKey = a => a.task_id + ':' + a.alert_id;
async function markAlertRead(alert) {
  // 先弹详情（v2 的 openAlertDetail 自带加载态），标记已读与列表重绘放后台，点击即刻有反馈
  openAlertDetail(alert).catch(e => flowStatus('读取告警失败：'+e.message));
  try {
    await api('/tasks/'+alert.task_id+'/view-alert/'+encodeURIComponent(alert.alert_id),post({}));
    readAlerts.add(alertKey(alert));
    setTimeout(() => { renderAlerts(); renderTask(); }, 0);
  } catch(e) { flowStatus('读取告警失败：'+e.message); }
}
function allAlerts() {
  return taskList.flatMap(task => (task.alerts || []).map(alert => ({...alert, task_id:task.task_id, taskLabel:(task.filename || '任务')+' · '+task.task_id.slice(0,8)}))).sort((a,b)=>(Date.parse(b.timestamp)||0)-(Date.parse(a.timestamp)||0));
}
function renderLatestAlerts(alerts) {
  const container = document.querySelector('#latest-alerts');
  container.replaceChildren();
  if (!alerts.length) { container.textContent = '暂无告警'; return; }
  for (const alert of alerts.slice(0, 5)) {
    const row = document.createElement('button');
    row.type = 'button';
    row.className = 'alert-line latest-alert ' + (readAlerts.has(alertKey(alert)) ? 'is-read' : 'is-unread');
    row.title = readAlerts.has(alertKey(alert)) ? '已读' : '点击标记为已读';
    row.setAttribute('aria-label', (readAlerts.has(alertKey(alert)) ? '已读：' : '未读：') + alert.title);
    row.addEventListener('click', () => markAlertRead(alert));
    const marker = document.createElement('i'); marker.className = 'sev ' + (alert.severity || 'low'); row.append(marker);
    const text = document.createElement('span'); text.innerHTML = '<b></b><small></small>';
    text.querySelector('b').textContent = alert.title;
    text.querySelector('small').textContent = (alert.target || alert.source || '') + (alert.technique ? ' · ' + alert.technique : '');
    row.append(text);
    const tag = document.createElement('span'); tag.className = 'alert-tag tag-' + (alert.severity || 'low'); tag.textContent = SEV_CN[alert.severity] || alert.severity || '未分级'; row.append(tag);
    container.append(row);
  }
}
function renderRiskPie(alerts, infoObservations = 0) {
  const pie = document.querySelector('#risk-pie');
  const legend = document.querySelector('#risk-legend');
  if (!pie || !legend) return;
  const levels = [['严重', 'critical', '#9f1239'], ['高危', 'high', '#b4232f'], ['中危', 'medium', '#d97a1f'], ['低危', 'low', '#0e7c8c'], ['信息', 'info', '#8a94a6']];
  const counts = levels.map(([, key]) => alerts.filter(a => a.severity === key).length);
  const total = counts.reduce((sum, count) => sum + count, 0);
  if (!total) {
    pie.style.background = '#eef1f6';
    pie.setAttribute('aria-label', '暂无危险等级数据');
    legend.replaceChildren();
    const empty = document.createElement('div'); empty.textContent = '暂无告警数据'; legend.append(empty);
    if (infoObservations) { const note = document.createElement('small'); note.textContent = `另有 ${infoObservations} 个信息级观察会话（不计告警）`; legend.append(note); }
    return;
  }
  let start = 0;
  const stops = levels.map(([, , color], index) => {
    const end = start + counts[index] / total * 360;
    const stop = `${color} ${start}deg ${end}deg`;
    start = end;
    return stop;
  });
  pie.style.background = `conic-gradient(${stops.join(', ')})`;
  pie.setAttribute('aria-label', levels.map(([label], index) => `${label}${Math.round(counts[index] / total * 100)}%`).join('，'));
  legend.replaceChildren();
  levels.forEach(([label, , color], index) => {
    const item = document.createElement('div');
    const dot = document.createElement('i'); dot.style.background = color;
    const name = document.createElement('span'); name.textContent = label;
    const value = document.createElement('b'); value.textContent = `${counts[index]} 条 · ${(counts[index] / total * 100).toFixed(1)}%`;
    if (!counts[index]) item.className = 'is-zero';
    item.append(dot, name, value); legend.append(item);
  });
  if (infoObservations) { const note = document.createElement('small'); note.textContent = `信息级观察：${infoObservations} 个低风险会话（M1 全量会话风险分 <20，不计告警）`; legend.append(note); }
}
async function refreshTasks() {
  const [loaded, reads] = await Promise.all([api('/tasks'),api('/read-alerts')]);
  taskList=loaded; reads.forEach(a=>readAlerts.add(alertKey(a)));
  if(currentTask) {
    const summary=taskList.find(t=>t.task_id===currentTask.task_id);
    if(summary) {
      const hasFullChains=(currentTask.chains||[]).some(c=>Array.isArray(c.stages));
      const preserved={chains:currentTask.chains,bundle:currentTask.bundle,alerts:currentTask.alerts,chain:currentTask.chain};
      currentTask={...currentTask,...summary};
      if(hasFullChains) Object.assign(currentTask,preserved);
    }
  }
  renderTask();
}
function renderTask() {
  if (currentTask) {
    const i = taskList.findIndex(t => t.task_id === currentTask.task_id);
    if (i < 0) taskList.push(currentTask); else taskList[i] = currentTask;
  }
  const table = document.querySelector('.task-detail'); table.replaceChildren();
  const head = document.createElement('div'); head.className = 'task-row header';
  for (const text of ['任务名称', '状态', '进度', '创建时间', '操作']) { const cell = document.createElement('span'); cell.textContent = text; head.append(cell); }
  table.append(head);
  if (!taskList.length) { const empty = document.createElement('div'); empty.className = 'task-row'; empty.textContent = '暂无任务，请先上传文件。'; table.append(empty); }
  for (const task of [...taskList].reverse()) {
    const row = document.createElement('div'); row.className = 'task-row';
    const name = document.createElement('span'); name.textContent = task.filename || task.task_id; name.style.fontWeight = '600'; row.append(name);
    const status = document.createElement('span'); status.className = 'status ' + (task.status === 'completed' ? 'done' : task.status === 'failed' ? 'failed' : 'running'); status.textContent = displayStage(task); row.append(status);
    const progressCell = document.createElement('div'); progressCell.className = 'progress';
    const bar = document.createElement('i'); bar.style.width = (task.progress || 0) + '%'; progressCell.append(bar);
    const percent = document.createElement('span'); percent.textContent = (task.progress || 0) + '%';
    const progressWrap = document.createElement('div'); progressWrap.style.display = 'flex'; progressWrap.style.alignItems = 'center'; progressWrap.style.gap = '8px';
    progressWrap.append(progressCell, percent); row.append(progressWrap);
    const created = document.createElement('span'); created.textContent = task.created_at ? new Date(task.created_at).toLocaleString('zh-CN', { hour12: false }) : '未提供'; row.append(created);
    const actions = document.createElement('span');
    const open = document.createElement('button'); open.textContent = task.task_id === currentTask?.task_id ? '当前任务' : '打开';
    open.onclick = () => selectTask(task); actions.append(open);
    if (task.status === 'failed') {
      const retry = document.createElement('button'); retry.textContent = '重试';
      retry.onclick = async () => { retry.disabled = true; try { await selectTask(await api('/tasks/' + task.task_id + '/retry',post({}))); } catch(e) { flowStatus(e.message); } finally { retry.disabled = false; } }; actions.append(retry);
    }
    row.append(actions);
    table.append(row);
  }
  const totalAlerts = allAlerts();
  const unreadCount = totalAlerts.filter(a => !readAlerts.has(alertKey(a))).length;
  const values = [taskList.filter(t => ['queued','running'].includes(t.status)).length,totalAlerts.length,taskList.reduce((n,t)=>n+(t.chains||[]).filter(c=>['high','critical'].includes(c.severity)).length,0),taskList.some(t=>t.status==='completed')?'已校验':'等待结果'];
  document.querySelectorAll('.metrics article>strong').forEach((el,i) => { if(i) el.textContent = values[i]; });
  document.querySelectorAll('.metrics article>small').forEach((el,i) => { if(i) el.textContent = '当前服务任务统计'; });
  document.querySelector('.hero-row p').textContent = `共 ${taskList.length} 个任务，${totalAlerts.length} 条告警；图表统计全部任务。`;
  document.querySelector('#nav-alert-count').textContent = unreadCount;
  document.querySelector('#notification-count').textContent = unreadCount;
  document.querySelector('#notification-count').hidden = unreadCount === 0;
  document.querySelector('#nav-alert-count').hidden = unreadCount === 0;
  renderLatestAlerts(totalAlerts);
  const infoObservations = taskList.reduce((sum, task) => sum + Number(task.bundle?.metrics?.informational_sessions || 0), 0);
  renderRiskPie(totalAlerts, infoObservations);
  renderOverview();
  const runningList = document.querySelector('.task-list'); runningList.replaceChildren();
  const running = taskList.filter(t => ['queued','running'].includes(t.status));
  if (!running.length) { runningList.textContent = '暂无进行中的任务'; }
  for (const task of running) {
    const row = document.createElement('div'); row.className = 'task';
    const ext = (task.filename || '').split('.').pop().slice(0, 3).toUpperCase();
    const icon = document.createElement('div'); icon.className = 'task-icon' + (ext === 'CSV' ? ' csv' : ext === 'JSO' ? ' json' : ''); icon.textContent = ext || '文件'; row.append(icon);
    const main = document.createElement('div'); main.className = 'task-main';
    const label = document.createElement('b'); label.textContent = task.filename || task.task_id; main.append(label);
    const bar = document.createElement('div'); bar.className = 'progress'; const fill = document.createElement('i'); fill.style.width = (task.progress || 0) + '%'; bar.append(fill); main.append(bar);
    row.append(main);
    const percent = document.createElement('strong'); percent.textContent = (task.progress || 0) + '%'; row.append(percent);
    row.addEventListener('click', () => selectTask(task));
    runningList.append(row);
  }
  document.querySelector('.threat-list').textContent = [...new Set(totalAlerts.map(a => a.technique || a.mitre || '未提供'))].join(' · ') || '暂无威胁统计';
}
async function selectTask(task) {
  selectionVersion++; if (stream) stream.close();
  currentTask = task; currentChain = null; taskAlerts = []; enableResults(false);
  localStorage.setItem('netguard.task',task.task_id);
  document.querySelector('#chat-messages').textContent = '当前任务：' + task.task_id;
  document.querySelector('#bundle-details').replaceChildren();
  document.querySelector('#chains select').replaceChildren();
  loadChatHistory(task.task_id, selectionVersion);
  document.querySelector('.chain-panel').textContent = '当前任务尚无攻击链结果';
  renderTask(); renderAlerts();
  if (task.status === 'completed') { try { await loadResults(); } catch(e) { flowStatus(e.message); } }
  else if (task.status === 'failed') flowStatus(displayStage(task));
  else subscribe();
}
function subscribe() {
  const version = selectionVersion;
  const connection = new EventSource('/api/v1/tasks/' + currentTask.task_id + '/stream'); stream = connection;
  connection.addEventListener('progress', async e => {
    if (version !== selectionVersion) return;
    Object.assign(currentTask,JSON.parse(e.data)); renderTask();
    flowStatus(displayStage(currentTask) + ' · ' + currentTask.progress + '%');
    if (currentTask.status === 'completed') {
      connection.close();
      try { await loadResults(); } catch(e) { flowStatus(e.message); }
    } else if (currentTask.status === 'failed') { connection.close(); flowStatus(displayStage(currentTask)); }
  });
  connection.onerror = () => { if (version === selectionVersion) flowStatus('连接中断，正在重新订阅进度…'); };
}
function renderAlerts() {
  const container = document.querySelector('#all-alerts'); container.replaceChildren();
  const selected = document.querySelector('#alerts select').selectedIndex;
  const levels = ['', 'high', 'medium', 'low', 'critical', 'info'];
  const search = document.querySelector('#alert-search')?.value.trim().toLowerCase() || '';
  const matching = allAlerts().filter(a => (!selected || a.severity === levels[selected]) && (!search || [a.title,a.source,a.target,a.tactic,a.technique,a.taskLabel].join(' ').toLowerCase().includes(search)));
  if (!matching.length) container.textContent = '当前筛选下没有告警';
  for (const alert of matching) {
    const row = document.createElement('div'); row.className = 'full-alert-row ' + (readAlerts.has(alertKey(alert)) ? 'is-read' : 'is-unread');
    row.title = readAlerts.has(alertKey(alert)) ? '已读' : '点击标记为已读';
    row.setAttribute('role', 'button'); row.tabIndex = 0;
    row.setAttribute('aria-label', (readAlerts.has(alertKey(alert)) ? '已读：' : '未读：') + alert.title + '，' + alert.taskLabel);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); markAlertRead(alert); } });
    row.addEventListener('click', () => markAlertRead(alert));
    const marker = document.createElement('i'); marker.className = 'unread-dot'; marker.setAttribute('aria-label', readAlerts.has(alertKey(alert)) ? '已读' : '未读'); row.append(marker);
    for (const text of [alert.title + '（' + alert.taskLabel + '）', alert.target, alert.mitre, alert.severity, alert.evidence]) {
      const cell = document.createElement('span'); cell.textContent = text; row.append(cell);
    }
    container.append(row);
  }
}
function renderChain() {
  const panel = document.querySelector('.chain-panel'); panel.replaceChildren();
  const heading = document.createElement('h3'); heading.textContent = '攻击阶段与证据'; panel.append(heading);
  if (!currentChain) { panel.append('当前任务没有攻击链'); return; }
  const flow = document.createElement('div'); flow.className = 'chain-flow';
  currentChain.nodes.forEach((node, i) => {
    if (i && !currentChain.stages) { const arrow = document.createElement('span'); arrow.textContent = ' · '; flow.append(arrow); }
    const box = document.createElement('button'); box.className = 'node'; const stage = currentChain.stages?.find(s => s.stage_id === node);
    box.textContent = stage ? stage.tactic + ' · ' + stage.technique : node;
    box.onclick = () => {
      const details = panel.querySelector('.node-evidence');
      if (stage) { details.textContent = `阶段 ${node} | ${stage.tactic} / ${stage.technique} | 置信度 ${stage.confidence} | ${stage.time_range.join(' 至 ')} | 证据：${stage.evidence_event_ids.join(', ')}`; return; }
      details.textContent = '节点 ' + node + '：' + taskAlerts.filter(a => a.source === node || a.target === node).map(a => '[' + a.alert_id + '] ' + a.evidence + ' · ' + a.mitre).join('；');
    }; flow.append(box);
  });
  const viewport = document.createElement('div'); viewport.className = 'graph-viewport'; viewport.append(flow); panel.append(viewport);
  const details = document.createElement('p'); details.className = 'node-evidence'; details.textContent = '点击节点查看关联证据'; panel.append(details);
  let zoom = 1;
  const controls = document.createElement('div'); controls.className = 'chain-actions';
  for (const [label, step] of [['放大',.2],['缩小',-.2],['复位',0]]) {
    const button = document.createElement('button'); button.textContent = label;
    button.onclick = () => { zoom = step ? Math.max(.6,Math.min(2,zoom+step)) : 1; flow.style.zoom = zoom; }; controls.append(button);
  }
  panel.append(controls);
  if (currentChain.edges) { const edges = document.createElement('p'); edges.textContent = '阶段关系：' + (currentChain.edges.map(e => e.join(' → ')).join('；') || '单阶段，无关联边'); panel.append(edges); }
  const explanation = document.createElement('p'); explanation.textContent = currentChain.explanation; panel.append(explanation);
  const evidence = document.createElement('p'); evidence.textContent = '关联证据：' + currentChain.evidence_ids.join(', '); panel.append(evidence);
}
async function loadResults() {
  const version = selectionVersion, id = currentTask.task_id;
  const task = await api('/tasks/' + id);
  const alerts = await api('/tasks/' + id + '/alerts');
  const chain = task.chain || null;
  if (version !== selectionVersion) return;
  currentTask = task; taskAlerts = alerts; currentChain = chain;
  renderTask(); renderAlerts(); renderChain(); renderBundle(); enableResults(true);
  flowStatus('结果已校验');
}
document.querySelector('#start-task').addEventListener('click', async () => {
  const button = document.querySelector('#start-task');
  const file = document.querySelector('#file-input').files[0];
  if (!file || !/\.(csv|pcap|pcapng|json|jsonl|xlsx)$/i.test(file.name) || !file.size || file.size > 2 * 1024 ** 3) {
    alert('请选择非空 CSV、XLSX、PCAP 或 JSON 文件，大小不超过 2 GB。'); return;
  }
  button.disabled = true; enableResults(false); if (stream) stream.close();
  try {
    button.textContent = '上传中…';
    const form = new FormData(); form.append('file', file);
    const uploaded = await api('/files', {method:'POST',body:form});
    currentTask = await api('/tasks', post({file_ids:[uploaded.file_id],query:document.querySelector('#task-note').value,analysis_mode:document.querySelector('#analysis-mode').value}));
    document.querySelector('#task-modal').classList.add('hidden');
    document.querySelector('#chat-messages').textContent = '正在分析，完成后可查询结果。';
    switchView('tasks'); renderTask();
    flowStatus('文件上传成功，已创建任务，正在分析…');
    await selectTask(currentTask);
  } catch (error) { flowStatus('操作失败：' + error.message); alert(error.message); }
  finally { button.disabled = false; button.textContent = '开始分析'; }
});
document.querySelector('#alerts select').addEventListener('change',renderAlerts);
document.querySelector('.icon-btn').onclick = () => { document.querySelector('#alerts select').selectedIndex = 0; document.querySelector('#alert-search').value=''; resetAlertFilters(); renderAlerts(); switchView('alerts'); };
document.querySelector('#show-results').onclick = () => switchView('report');
const chatPanel = document.querySelector('#chat-panel');
function openDrawer(){ chatPanel.classList.remove('hidden'); const m=document.getElementById('drawer-mask'); if(m)m.classList.remove('hidden'); document.body.classList.add('drawer-open'); const i=document.getElementById('chat-input'); if(i&&currentTask?.status==='completed')setTimeout(()=>i.focus(),50); }
function closeDrawer(){ chatPanel.classList.add('hidden'); const m=document.getElementById('drawer-mask'); if(m)m.classList.add('hidden'); document.body.classList.remove('drawer-open'); }
document.querySelector('#ask-task').onclick = openDrawer;
document.querySelector('#open-chat').onclick = () => {
  if (currentTask?.status !== 'completed') { flowStatus('请先完成任务。'); return; }
  openDrawer();
};
document.querySelector('#close-chat').onclick = closeDrawer;
const _dm=document.getElementById('drawer-mask'); if(_dm)_dm.onclick=closeDrawer;
async function downloadReport(format, chainId = '') {
  if (!currentTask || currentTask.status !== 'completed') { flowStatus('请先完成分析任务。'); return; }
  try {
    const params = new URLSearchParams({format}); if (chainId) params.set('chain_id', chainId);
    const response = await fetch('/api/v1/reports/' + currentTask.task_id + '?' + params);
    if (!response.ok) throw new Error('报告导出失败');
    const url = URL.createObjectURL(await response.blob());
    const link = document.createElement('a'); link.href = url;
    link.download = chainId ? 'netguard-chain-' + chainId + '.json' :
      (format === 'pdf' ? 'netguard-risk-report-' : 'netguard-evidence-') + currentTask.task_id.slice(0,8) + '.' + format;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch(error) { flowStatus(error.message); }
}
document.querySelector('#report-json').onclick = () => downloadReport('json');
document.querySelector('#report-pdf').onclick = () => downloadReport('pdf');
document.querySelector('#export-alerts').onclick = () => downloadReport('json');
document.querySelector('#export-chain').onclick = () => downloadReport('json', currentChain?.chain_id || '');
// 分析结果页内的导出/提问按钮
{ const rj=document.getElementById('report-json2'), rp=document.getElementById('report-pdf2'), ar=document.getElementById('ask-report');
  if(rj)rj.onclick=()=>downloadReport('json'); if(rp)rp.onclick=()=>downloadReport('pdf'); if(ar)ar.onclick=()=>{ if(currentTask?.status!=='completed'){flowStatus('请先完成任务。');return;} openDrawer(); }; }
document.querySelector('#send-chat').onclick = async () => {
  const input = document.querySelector('#chat-input'), button = document.querySelector('#send-chat');
  if (!input.value.trim() || currentTask?.status !== 'completed') return;
  const chatVersion=selectionVersion;
  const message = input.value.trim(); input.value = ''; button.disabled = true;
  const messages = document.querySelector('#chat-messages');
  const question = document.createElement('p'); question.textContent = '你：' + message; messages.append(question);
  const answer = document.createElement('p'); answer.className = 'assistant-msg'; messages.append(answer);
  try {
    const response = await fetch('/api/v1/chat', post({task_id:currentTask.task_id,chain_id:currentChain?.chain_id,message}));
    if (!response.ok) throw new Error('对话请求失败');
    const reader = response.body.getReader(), decoder = new TextDecoder(); let buffer = '', doneEvent = false, answerText = '';
    while (true) {
      const {value,done} = await reader.read(); if(chatVersion!==selectionVersion) { await reader.cancel(); return; } if (done) break;
      buffer += decoder.decode(value,{stream:true}).replace(/\r\n/g,'\n');
      let boundary;
      while ((boundary = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0,boundary); buffer = buffer.slice(boundary+2);
        const type = block.match(/^event: (.+)$/m)?.[1];
        const dataLine = block.match(/^data: (.+)$/m)?.[1]; if (!dataLine) continue;
        const data = JSON.parse(dataLine);
        if (type === 'delta') { answerText += data.text; answer.textContent = displayAnswer(answerText); }
        if (type === 'evidence') for (const item of data.items) {
          const evidence = document.createElement('p'); evidence.textContent = '证据 [' + item.alert_id + ']：' + item.evidence; messages.append(evidence);
        }
        if (type === 'done') { doneEvent = true; }
        messages.scrollTop = messages.scrollHeight;
      }
    }
    if (!doneEvent) throw new Error('响应中断，请重试');
  } catch(error) { answer.textContent += '\n' + error.message; }
  finally { button.disabled = currentTask?.status !== 'completed'; }
};
document.querySelector('#chat-input').addEventListener('keydown', e => { if (e.key === 'Enter') document.querySelector('#send-chat').click(); });
const dropZone = document.querySelector('#upload-box');
dropZone.addEventListener('dragover',e => e.preventDefault());
dropZone.addEventListener('drop',e => { e.preventDefault(); document.querySelector('#file-input').files = e.dataTransfer.files; document.querySelector('#file-input').dispatchEvent(new Event('change')); });

const searchInput = document.createElement('input'); searchInput.id = 'alert-search'; searchInput.placeholder = '搜索攻击者、资产、战术、技术或任务'; searchInput.setAttribute('aria-label','搜索告警');
searchInput.oninput = renderAlerts; document.querySelector('#alerts .filter-row').prepend(searchInput);
for (const [value,label] of [['critical','严重'],['info','信息']]) { const option = document.createElement('option'); option.textContent=label; document.querySelector('#alerts select').append(option); }
const chainSelector = document.querySelector('#chains select');
// 攻击链页标签切换
document.querySelectorAll('.chain-tab').forEach(btn=>btn.addEventListener('click',()=>{
  document.querySelectorAll('.chain-tab').forEach(b=>b.classList.toggle('active',b===btn));
  const key=btn.dataset.tab;
  document.querySelectorAll('#chains .tab-panel').forEach(p=>p.classList.toggle('hidden',p.dataset.panel!==key));
}));
chainSelector.onchange = async () => {
  const id=chainSelector.value;
  currentChain=currentTask?.chains?.find(c=>c.chain_id===id)||null;
  if(currentChain && !Array.isArray(currentChain.stages)) {
    document.querySelector('.chain-panel').textContent='正在载入攻击阶段…';
    try {
      const full=await api('/attack-chains/'+encodeURIComponent(id));
      currentChain=full;
      const index=currentTask.chains.findIndex(c=>c.chain_id===id);
      if(index>=0) currentTask.chains[index]=full;
    } catch(error) { flowStatus('攻击链加载失败：'+error.message); }
  }
  renderChain();
};
const reportPanel = document.createElement('article'); reportPanel.className='panel'; reportPanel.id='bundle-details'; document.querySelector('#chains').append(reportPanel);
function renderBundle() {
  chainSelector.replaceChildren();
  for (const chain of currentTask.chains || []) { const option=document.createElement('option'); option.value=chain.chain_id; option.textContent=chain.chain_id; chainSelector.append(option); }
  reportPanel.replaceChildren();
  const bundle=currentTask.bundle;
  if (!bundle) { reportPanel.textContent='历史演示任务：没有 v2 文件结果。请新建任务。'; return; }
  function section(title, text) { const heading=document.createElement('h3'); heading.textContent=title; const paragraph=document.createElement('p'); paragraph.textContent=text; reportPanel.append(heading,paragraph); }
  section('运营总结', `原始数量：${bundle.metrics.raw_count ?? '未提供'}；降噪后：${bundle.metrics.denoised_count ?? '未提供'}；可疑事件：${bundle.metrics.suspicious_count ?? '未提供'}；攻击链：${bundle.chains.length}；画像：${bundle.profiles.length}；M1+M2 全流程耗时：${bundle.metrics.duration_seconds ?? '未提供'} 秒`);
  section('攻击者画像',bundle.profiles.map(p => JSON.stringify(p)).join('\n') || '暂无攻击者画像');
  section('风险报告',bundle.report.summary || '未提供');
  section('建议及来源',(bundle.report.recommended_actions || []).map(a=>`[${a.source}] ${a.text}`).join('\n') || '未提供');
  section('证据索引',bundle.evidence.map(e=>`[${e.event_id}] ${e.summary || ''}`).join('\n'));
  section('处理版本',JSON.stringify(bundle.versions));
}
(async () => {
  // boot 自动恢复任务。曾出现过一次脚本加载竞态（flow 停在初始文案、任务未选中，
  // 看起来像"功能丢了"），故失败后自动重试一次再报错。
  const boot = async () => {
    await refreshTasks();
    const saved = localStorage.getItem('netguard.task');
    const task = taskList.find(t => t.task_id === saved) || taskList.at(-1);
    if (task) await selectTask(task);
    else { renderAlerts(); document.querySelector('.chain-panel').textContent = '暂无攻击链，请先完成分析任务。'; }
  };
  try {
    await boot();
  } catch(e) {
    flowStatus('启动异常（' + e.message + '），2 秒后自动重试…');
    setTimeout(async () => {
      try { await boot(); }
      catch(e2) { flowStatus('服务连接失败：' + e2.message + '。请刷新重试。'); }
    }, 2000);
  }
})();
