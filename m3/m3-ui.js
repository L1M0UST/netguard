// M3 renders producer-supplied facts and relationships only.
const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
// 等级主色（与 styles.css :root --sev-* 同源，SVG 无法用 CSS 变量时使用）
const SEV_HEX = { critical: '#9f1239', high: '#b4232f', medium: '#a05a12', low: '#0e7c8c', info: '#4b5b74' };
const ANALYSIS_MODE_CN = {local:'仅本地模型', cloud:'仅互联网模型', hybrid:'本地初判 + 云端复核'};
function analysisModeCN(mode) { return ANALYSIS_MODE_CN[mode] || ANALYSIS_MODE_CN.hybrid; }
function sevCN(sev) { return SEV_CN[sev] || sev || '未分级'; }
function fmtDuration(seconds) {
  if (seconds == null || isNaN(Number(seconds))) return '未提供';
  const v = Math.round(Number(seconds));
  if (v < 60) return v + ' 秒';
  const m = Math.round(v / 60);
  if (m < 60) return m + ' 分钟';
  return Math.round(m / 60 * 10) / 10 + ' 小时';
}
function fmtTime(ts) {
  const t = Date.parse(ts);
  if (isNaN(t)) return ts || '时间未提供';
  const d = new Date(t), p = n => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}
function sortChains(chains) {
  return (chains || []).slice().sort((a, b) =>
    ((b.stage_count ?? b.stages?.length ?? 0) > 1) - ((a.stage_count ?? a.stages?.length ?? 0) > 1) ||
    (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) ||
    ((b.confidence_card?.score ?? b.risk_score) || 0) - ((a.confidence_card?.score ?? a.risk_score) || 0));
}
function sortActions(actions) {
  return (actions || []).slice().sort((a, b) =>
    (SEV_ORDER[a.priority] ?? 9) - (SEV_ORDER[b.priority] ?? 9));
}
function element(tag, text, parent, cls) {
  const node=document.createElement(tag); if(text!==undefined) node.textContent=text;
  if(cls) node.className=cls; if(parent) parent.append(node); return node;
}
function details(parent, title, data) {
  const empty = data == null || ((Array.isArray(data) || typeof data === 'object') && !Object.keys(data).length);
  const section=element('section',undefined,parent,'detail-section'); element('h3',title,section);
  element('pre', empty ? '暂无' : typeof data==='string'?data:JSON.stringify(data,null,2),section); return section;
}

/* ══ MITRE ATT&CK 中文映射层：中文名为主、编号作徽章，让中文母语者一眼看懂 ══
   数据里的 tactic/technique 形如 "TA0001 Initial Access" / "T1190 Exploit ..." / "Unclassified"。 */
const ATT_TACTIC = {
  TA0001:'初始访问', TA0002:'执行', TA0003:'持久化', TA0004:'权限提升',
  TA0005:'防御规避', TA0006:'凭证访问', TA0007:'发现与探测', TA0008:'横向移动',
  TA0009:'信息收集', TA0010:'数据外传', TA0011:'命令与控制', TA0012:'影响破坏',
  TA0040:'受影响的数据', TA0043:'未归类战术',
};
const ATT_TECH = {
  T1190:'利用面向公众的应用程序漏洞', T1059:'命令与脚本解释器执行', T1083:'文件与目录发现',
  T1133:'外部远程服务', T1203:'客户端程序漏洞利用执行', T1068:'漏洞利用提权',
  T1041:'经 C2 通道外传数据', T1048:'经备用协议外传数据', T1567:'经 Web 服务外传数据',
  T1110:'暴力破解口令', T1078:'使用有效账户', T1595:'主动扫描探测', T1505:'服务端组件 Web Shell',
  T1204:'用户执行恶意载荷', T1106:'原生 API 调用执行', T1053:'计划任务/作业',
  T1021:'远程服务登录', T1046:'远程服务侦察',
};
// 解析 "TA0001 Initial Access" / "T1190 Exploit ..." / "Unclassified" → {cn, code}
function attCn(raw) {
  const s = String(raw || '').trim();
  if (!s || /^unclassified$/i.test(s)) return { cn: '未归类行为', code: '' };
  const m = s.match(/^(T[A-Z]?\d+(?:\.\d+)?)\b\s*(.*)$/i);
  if (!m) return { cn: s, code: '' };
  const code = m[1].toUpperCase();
  const cn = ATT_TECH[code] || ATT_TACTIC[code] || (m[2] ? m[2].trim() : 'ATT&CK ' + code);
  // 战术码 TAxxxx 与技术码同表兜底；技术自带英文尾名时优先中文，缺失才留英文
  if (ATT_TACTIC[code]) return { cn: ATT_TACTIC[code], code };
  return { cn, code };
}
// 返回带徽章的 HTML 片段（用于 innerHTML 场景）；调用方需保证内容已可信
function attBadge(raw) {
  const { cn, code } = attCn(raw);
  return code ? `<span class="att-name">${cn}</span><code class="att-code">${code}</code>`
              : `<span class="att-name">${cn}</span>`;
}
const SOURCE_CN = { rule: '规则引擎', m1: '接入初筛', m2: '攻击关联研判', llm: '模型研判', 'llm_generated':'模型研判', rule_based:'规则引擎', knowledge_base:'安全知识库', analyst_verified:'人工确认', 'm1-session':'会话初筛' };
function srcCn(s) { return SOURCE_CN[s] || s || '系统'; }
// M1 规则键 → 展示名（判断依据块用）；ml_ 前缀=ML 检测器对同一规则的判定
const RULE_CN = {
  sql_injection:'SQL 注入特征', command_injection:'命令注入特征', java_deserialization:'Java 反序列化特征',
  path_traversal:'路径遍历特征', file_inclusion:'文件包含特征', file_upload:'文件上传特征',
  xss:'XSS 脚本特征', csrf:'CSRF 缺陷特征', scanner:'扫描器特征', flow_scan:'流量行为分析',
  multi_path_scan:'多路径探测', prompt_injection:'提示注入', ioc_match:'威胁情报命中', suspicious:'会话行为异常',
};
function ruleCn(r) {
  const s = String(r || '');
  if (s.startsWith('ml_')) return 'ML 模型·' + (RULE_CN[s.slice(3)] || s.slice(3));
  return RULE_CN[s] || s;
}
const overviewFacts=element('article',undefined,document.querySelector('#overview'),'panel task-facts');
function renderOverview() {
  overviewFacts.replaceChildren(); element('h3','当前任务概览',overviewFacts);
  if(!currentTask) { element('p','请选择分析任务',overviewFacts); return; }
  element('p',`${currentTask.filename} · ${displayStage(currentTask)}`,overviewFacts);
  const b=currentTask.bundle, m=b?.metrics||{};
  if(!b) { element('p','等待分析结果。',overviewFacts); return; }
  const stats=element('div',undefined,overviewFacts,'fact-grid');
  const taskAlerts=b.alerts||currentTask.alerts||[];
  const chainCount=(currentTask.chains||b.chains||[]).length;
  const values=[['原始事件',m.raw_count],['降噪后事件',m.denoised_count],['可疑事件',m.suspicious_count],['高危/严重告警',taskAlerts.filter(a=>['high','critical'].includes(a.severity)).length],['攻击链',chainCount],['攻击者画像',b.profiles.length],['M1+M2 全流程耗时',fmtDuration(m.duration_seconds)]];
  values.forEach(([name,v])=>{const card=element('div',undefined,stats);element('small',name,card);element('strong',v??'未提供',card);});
  const iocs=b.profiles.flatMap(p=>p.observed_iocs||p.ioc_hits||[]);
  const focus=element('section',undefined,overviewFacts,'focus-indicators');
  element('h3','重点威胁指标',focus);
  element('p','用于快速定位最值得先核查的来源、受害资产和攻击类型；它是处置入口，不是新的风险评分。',focus,'panel-intro');
  const explicit=m.top_iocs||iocs.slice(0,10);
  if(explicit.length) details(focus,'情报命中',explicit);
  else {
    const attackers=new Map(),targets=new Map(),types=new Map();
    taskAlerts.forEach(a=>{if(a.source)attackers.set(a.source,(attackers.get(a.source)||0)+1);if(a.target)targets.set(a.target,(targets.get(a.target)||0)+1);const t=a.attack_type||a.technique;if(t)types.set(t,(types.get(t)||0)+1);});
    const top=map=>[...map.entries()].sort((a,c)=>c[1]-a[1])[0];
    const grid=element('div',undefined,focus,'indicator-grid');
    [['高频攻击源',top(attackers)],['受影响最多资产',top(targets)],['主要攻击类型',top(types)]].forEach(([label,item])=>{const card=element('div',undefined,grid);element('small',label,card);element('b',item?.[0]||'暂无',card);element('span',item?item[1]+' 条关联告警':'当前任务没有可归纳数据',card);});
  }
}
const baseRenderTask=renderTask;
const analysisSteps=[
  '正在整理请求时间、方法与 User-Agent…',
  '正在关联来源 IP、目标 IP 与访问路径…',
  '正在核查 XSS、SQL 注入相关请求…',
  '正在核查目录遍历与 Java 反序列化相关请求…'
];
const analysisRuns=new Map();
let analysisTimer=null;
function analysisPresentation(task, now=Date.now()) {
  if(!task) return {progress:0,lines:[]};
  const pending=['queued','running'].includes(task.status);
  let run=analysisRuns.get(task.task_id);
  if(pending && (!run || !run.pending)) {
    run={started:now,pending:true,progress:0};
    analysisRuns.set(task.task_id,run);
  }
  if(!pending) {
    if(run) run.pending=false;
    return {progress:task.status==='completed'?100:run?.progress||0,lines:[]};
  }
  const elapsed=Math.max(0,now-run.started);
  run.progress=Math.min(75,Math.floor(elapsed/160));
  const cycleDuration=4000;
  const phase=elapsed%cycleDuration;
  const line=analysisSteps[Math.floor(elapsed/cycleDuration)%analysisSteps.length];
  const lines=phase<3500?[line.slice(0,Math.floor(phase/65))]:[];
  return {progress:run.progress,lines};
}
function renderThinkingStatus() {
  const card=document.querySelector('.metrics article');
  const task=currentTask || taskList.at(-1);
  const pending=task && ['queued','running'].includes(task.status);
  const presentation=analysisPresentation(task);
  if(pending && analysisTimer===null) analysisTimer=setInterval(renderThinkingStatus,100);
  if(!pending && analysisTimer!==null) {clearInterval(analysisTimer);analysisTimer=null;}
  card.classList.add('thinking-card');
  card.classList.toggle('is-thinking',Boolean(pending));
  card.querySelector('.metric-label').textContent='任务分析';
  const status=card.querySelector('strong');
  status.setAttribute('role','status');
  status.setAttribute('aria-live','polite');
  const text=!task?'等待分析':pending?'正在分析':task.status==='completed'?'分析完成':task.status==='failed'?'分析失败':'等待分析';
  let label=status.querySelector('.thinking-label');
  let circle=status.querySelector('.thinking-circle');
  if(!label || !circle) {
    status.replaceChildren();
    label=element('span',undefined,status,'thinking-label');
    circle=element('span',undefined,status,'thinking-circle');
    circle.setAttribute('role','progressbar');
    circle.setAttribute('aria-label','任务分析进度');
    circle.setAttribute('aria-valuemin','0');
    circle.setAttribute('aria-valuemax','100');
  }
  if(label.textContent!==text)label.textContent=text;
  const progress=presentation.progress;
  circle.style.setProperty('--thinking-progress',progress+'%');
  circle.setAttribute('aria-valuenow',String(progress));
  circle.setAttribute('aria-valuetext',text+'，'+progress+'%');
  const detail=card.querySelector('small');
  const phase=task ? displayStage(task) : '等待分析进度';
  detail.textContent=!task?'新建任务后实时显示分析进度':`${task.filename || task.task_id} · ${pending ? progress+'%' : phase}`;
  detail.title=detail.textContent;
  let output=card.querySelector('.analysis-stream');
  if(!output) output=element('div',undefined,card,'analysis-stream');
  output.hidden=!pending;
  const lines=presentation.lines.join('\n');
  if(output.textContent!==lines) output.textContent=lines;
  card.setAttribute('aria-label','当前任务分析状态');

}
renderTask=function() {
  baseRenderTask();
  renderThinkingStatus();
  const counts=new Map(); allAlerts().forEach(a=>{const key=a.attack_type||a.technique||'未提供';counts.set(key,(counts.get(key)||0)+1);});
  const target=document.querySelector('.threat-list'); target.replaceChildren();
  const total=allAlerts().length;
  if(!total) target.textContent='暂无威胁统计';
  const palette=['#23bdd0','#f39a45','#8b6df4','#eb5b62','#3768ef','#31b984'];
  [...counts.entries()].sort((a,b)=>b[1]-a[1]).slice(0,10).forEach(([name,count],i)=>{
    const row=element('div',undefined,target);
    element('span',undefined,row,'dot').style.background=palette[i%palette.length];
    element('label',name,row);
    element('b',`${count} 条 · ${(count/total*100).toFixed(1)}%`,row);
    const bar=element('div',undefined,row,'bar');
    const fill=element('i',undefined,bar); fill.style.width=(count/total*100)+'%';
    fill.style.background=palette[i%palette.length];
  });
  document.querySelector('.last-update').textContent='刷新于 '+new Date().toLocaleTimeString();
};

const filters=document.querySelector('#alerts .filter-row');
const filterInputs={};
const sortSelect=element('select',undefined,filters); sortSelect.id='alert-sort'; sortSelect.setAttribute('aria-label','告警排序字段');
[['time','按时间'],['target','按目标资产'],['severity','按等级']].forEach(([v,l])=>{const o=element('option',l,sortSelect);o.value=v;});
const sortDirection=element('select',undefined,filters); sortDirection.id='alert-sort-direction'; sortDirection.setAttribute('aria-label','排序方向');
[['desc','降序'],['asc','升序']].forEach(([v,l])=>{const o=element('option',l,sortDirection);o.value=v;});
sortSelect.onchange=sortDirection.onchange=()=>{alertPage=1;renderAlerts();};
for(const [key,label,type] of [['from','起始时间','datetime-local'],['to','结束时间','datetime-local'],['confidence','最低置信度 0–1','number']]) {
  const labelNode=element('label',label,filters); const input=element('input',undefined,labelNode); input.type=type; input.setAttribute('aria-label',label); filterInputs[key]=input;
  if(type==='number') {input.min=0;input.max=1;input.step=.05;}
  input.onchange=()=>{alertPage=1;renderAlerts();};
}
let alertPage=1; const pageSize=50;
function resetAlertFilters() { Object.values(filterInputs).forEach(i=>i.value=''); alertPage=1; }
const pager=element('div',undefined,document.querySelector('#alerts .panel'),'chain-actions');
renderAlerts=function() {
  const container=document.querySelector('#all-alerts'); container.replaceChildren(); pager.replaceChildren();
  const levels=['','high','medium','low','critical','info']; const severity=levels[document.querySelector('#alerts select').selectedIndex];
  const q=document.querySelector('#alert-search').value.trim().toLowerCase();
  const matching=allAlerts().filter(a=>{
    if(severity && a.severity!==severity) return false;
    if(q && ![a.title,a.source,a.target,a.tactic,a.technique,a.taskLabel,a.alert_id].join(' ').toLowerCase().includes(q)) return false;
    if(filterInputs.confidence.value!=='' && (a.confidence===undefined||a.confidence<Number(filterInputs.confidence.value))) return false;
    const time=Date.parse(a.timestamp);
    if(filterInputs.from.value && !(time>=Date.parse(filterInputs.from.value))) return false;
    if(filterInputs.to.value && !(time<=Date.parse(filterInputs.to.value))) return false;
    return true;
  });
  const direction=sortDirection.value==='asc'?1:-1;
  const severityRank={critical:5,high:4,medium:3,low:2,info:1};
  matching.sort((a,b)=>direction*(sortSelect.value==='target'
    ? String(a.target||'').localeCompare(String(b.target||''),'zh-CN')
    : sortSelect.value==='severity'
      ? (severityRank[a.severity]||0)-(severityRank[b.severity]||0)
      : (Date.parse(a.timestamp)||0)-(Date.parse(b.timestamp)||0)));
  window.__matchingAlerts = matching;
  const pages=Math.max(1,Math.ceil(matching.length/pageSize));alertPage=Math.min(alertPage,pages);
  const head=element('div',undefined,container,'alert-table-head');
  element('span','',head);['告警','目标资产','ATT&CK 技术','等级','时间'].forEach(v=>element('span',v,head));
  if(!matching.length) element('div','当前筛选下没有告警',container);
  matching.slice((alertPage-1)*pageSize,alertPage*pageSize).forEach(a=>{
    const row=element('button',undefined,container,'full-alert-row '+(readAlerts.has(alertKey(a))?'is-read':'is-unread'));row.type='button';
    element('i',undefined,row,'unread-dot');
    element('span',a.title+'（'+a.taskLabel+'）',row);
    element('span',a.target||'未提供',row);
    element('span',a.technique||'未提供',row);
    element('span',sevCN(a.severity),row,'alert-sev '+(a.severity||'info'));
    element('span',fmtTime(a.timestamp),row);
    row.title=(readAlerts.has(alertKey(a))?'已读：':'未读：')+a.title+' · 点击标记为已读';
    row.onclick=()=>markAlertRead(a);
  });
  element('span',`共 ${matching.length} 条 · 第 ${alertPage}/${pages} 页`,pager);
  for(const [label,step] of [['上一页',-1],['下一页',1]]) {const btn=element('button',label,pager);btn.disabled=step<0?alertPage===1:alertPage===pages;btn.onclick=()=>{alertPage+=step;renderAlerts();};}
};
document.querySelector('#alert-search').oninput=()=>{alertPage=1;renderAlerts();};

const alertDialog=element('dialog',undefined,document.body,'alert-dialog');
async function openAlertDetail(alert) {
  const d=await api('/tasks/'+alert.task_id+'/alert/'+encodeURIComponent(alert.alert_id));
  alertDialog.replaceChildren();
  const top=element('div',undefined,alertDialog,'alert-detail-top');
  const heading=element('div',undefined,top); element('small','告警证据详情',heading); element('h2',d.title,heading);
  const close=element('button','关闭',top,'secondary-btn');close.onclick=()=>alertDialog.close();
  const facts=element('div',undefined,alertDialog,'alert-detail-facts');
  [['综合等级',sevCN(d.severity),'alert-sev '+(d.severity||'info')],['规则信号',d.signal_severity?sevCN(d.signal_severity):'一致',''],
   ['攻击源',d.source||'未提供',''],['受害资产',d.target||'未提供',''],['发生时间',fmtTime(d.timestamp),''],['置信度',d.confidence==null?'未提供':Math.round(d.confidence*100)+'%','']]
    .forEach(([label,value,cls])=>{const item=element('div',undefined,facts);element('small',label,item);element('b',value,item,cls);});
  const why=element('section',undefined,alertDialog,'alert-detail-callout');element('b','为什么需要关注',why);element('p',riskReasonCn(d.risk_reason||d.reason),why);
  // 单事件研判报告：本地垂域模型按需生成（能力②）；失败回退确定性汇总，来源诚实标注
  const reportSec=element('section',undefined,alertDialog,'alert-detail-callout');
  const reportHead=element('div',undefined,reportSec,'alert-report-head');
  element('b','单事件研判报告',reportHead);
  const genBtn=element('button','生成研判报告',reportHead,'secondary-btn');
  const reportOut=element('div',undefined,reportSec,'alert-event-report');
  element('small','四段研判（事件概述/攻击证据/风险等级/处置建议）：本地垂域模型只做文字组织，所有数字取自系统统计；本地模型未启用时给出确定性汇总。',reportOut);
  genBtn.onclick=async()=>{
    genBtn.disabled=true;genBtn.textContent='本地模型研判中（约 10~30 秒）…';
    try{
      const rep=await api('/tasks/'+alert.task_id+'/alert/'+encodeURIComponent(alert.alert_id)+'/event-report',post({}));
      reportOut.replaceChildren();
      const badge=element('span',rep.source==='cqsec'?'来源：本地垂域模型':'来源：确定性汇总（本地模型未启用）',reportOut,'meta-badge');
      if(rep.cached) badge.textContent+='（缓存）';
      if(rep.note) element('small',rep.note,reportOut,'corr-note');
      element('pre',rep.report||'（空）',reportOut,'event-report-text');
      genBtn.textContent='重新生成';
    }catch(e){
      element('p','生成失败：'+e.message,reportOut,'corr-note');
      genBtn.textContent='重试';
    }
    genBtn.disabled=false;
  };
  const related=d.related_chains||[];
  element('h3','关联攻击链（'+related.length+'）',alertDialog);
  const links=element('div',undefined,alertDialog,'alert-detail-links');
  related.forEach(c=>{const item=element('div',undefined,links,'alert-chain-link');
    element('div',(c.chain_id||'攻击链')+' · '+sevCN(c.severity)+' · '+((c.stages||[]).length||c.stage_count||'—')+' 阶段'+((c.confidence_card||{}).score!=null?' · 风险分 '+c.confidence_card.score:''),item);
    const button=element('button','在路径图中打开',item,'secondary-btn');button.onclick=async()=>{currentChain=await api('/attack-chains/'+encodeURIComponent(c.chain_id));populateChainSelector();renderChain();alertDialog.close();switchView('chains');};
  });
  if(!related.length) element('p','当前告警尚未关联攻击链。',links,'empty-state');
  const evidence=d.evidence||[]; element('h3','原始证据引用（'+evidence.length+'）',alertDialog);
  const evidenceList=element('div',undefined,alertDialog,'alert-evidence-list');
  evidence.slice(0,12).forEach((e,i)=>{const item=element('article',undefined,evidenceList);element('b','证据 '+(i+1)+' · '+(e.event_id||'未编号'),item);element('p',e.summary||'未提供摘要',item);});
  if(!evidence.length) element('p','暂无可展示的原始证据引用。',evidenceList,'empty-state');
  const actions=d.recommended_actions||[]; const technique=String(d.technique||d.mitre||'').split(' ')[0];
  const matched=actions.filter(a=>(a.related_techniques||[]).some(code=>String(code).split(' ')[0]===technique));
  const shown=(matched.length?matched:actions).slice(0,4); element('h3','建议处置',alertDialog);
  const advice=element('div',undefined,alertDialog,'alert-advice-list');
  shown.forEach(a=>{const zh=adviceCn(a),item=element('article',undefined,advice);element('b',priorityCN(a.priority)+' · '+zh.title,item);element('p',zh.text,item);element('small','依据：'+(a.related_techniques?.length?attCodes(a.related_techniques,ATT_TECH):'通用防护要求')+' · 来源 '+srcCn(a.source),item);});
  if(!shown.length) element('p','暂无结构化处置建议。',advice,'empty-state');
  if((d.vulnerabilities||[]).length){element('h3','关联漏洞',alertDialog);const vulns=element('div',undefined,alertDialog,'alert-detail-links');(d.vulnerabilities||[]).forEach(v=>element('span',typeof v==='string'?v:JSON.stringify(v),vulns,'meta-badge'));}
  if(!alertDialog.open) alertDialog.showModal();
}

// SVG 无自动换行：按显示宽度截断，避免溢出方框（中文按 2 宽计）
function svgClip(str, maxUnits) {
  let w = 0, out = '';
  for (const ch of String(str)) { w += /[\u4e00-\u9fff，。（）]/.test(ch) ? 2 : 1; if (w > maxUnits) return out + '…'; out += ch; }
  return out;
}
// —— 关联理由中文化：M2 关联引擎的 LinkDecision reasons 是确定性英文短语，展示层映射 ——
const CORR_REASON_PATTERNS = [
  [/^attacker block (.+)$/i, '攻击源分块 $1'],
  [/^victim block (.+)$/i, '受害目标分块 $1'],
  [/^identical attacker (.+)$/i, '同一攻击源 $1'],
  [/^attackers inside the same subnet \((.+)\/(.+)\)$/i, '攻击源同网段（$1 / $2）'],
  [/^identical victim (.+)$/i, '同一受害资产 $1'],
  [/^victims inside the same subnet \((.+)\/(.+)\)$/i, '受害资产同网段（$1 / $2）'],
  [/^same destination port (.+)$/i, '相同目的端口 $1'],
  [/^same (?:Module 1 )?session (.+)$/i, '同一会话 $1'],
  [/^shared IOC (.+)$/i, '共享威胁情报 $1'],
  [/^behaviour categories (.+?) -> (.+?) \(affinity=([\d.]+)\)$/i, '行为类别 $1 → $2（亲和度 $3）'],
  [/^similar rule hits \(similarity=([\d.]+)\)$/i, '命中相似规则（相似度 $1）'],
  [/^events occur within (\d+)s \(inside the correlation window\)$/i, '间隔 $1 秒（关联窗口内）'],
  [/^events are (\d+)s apart \(inside the extended gap limit\)$/i, '间隔 $1 秒（扩展窗口内）'],
];
function corrReasonCn(text) {
  const s = String(text || '');
  for (const [re, rep] of CORR_REASON_PATTERNS) { if (re.test(s)) return s.replace(re, rep); }
  return s;
}
// —— 不确定项/缺失证据中文化（chain.uncertainties 里的已知模式；未知原文保留） ——
const UNCERTAINTY_PATTERNS = [
  [/^Multiple ATT&CK stages were proposed but only one evidence event supports/i, '模型提出了多个阶段，但仅有一条证据事件支持，链已折叠为单阶段'],
  [/^LLM analysis was unavailable/i, '大模型研判不可用，本链按确定性规则构建'],
  [/degraded to deterministic rules/i, '大模型研判不可用，已按确定性规则建链'],
];
function uncertaintyCn(text) {
  const s = String(text || '');
  for (const [re, rep] of UNCERTAINTY_PATTERNS) { if (re.test(s)) return rep; }
  return s;
}
renderChain=function() {
  const panel=document.getElementById('tab-path')||document.querySelector('.chain-panel'); panel.replaceChildren();
  if(!currentChain) {element('p','当前任务没有攻击链。请在上方选择一条链，或先在"分析任务"里完成任务。',panel);return;}
  const card=currentChain.confidence_card||{};
  const intro=element('p','下方按时间顺序展示这条攻击链的每个阶段——每一步对方做了什么（ATT&CK 战术/技术）、置信度多少。点击任一阶段可在下方展开该步的原始证据。',panel,'panel-intro');
  const meta=element('div',undefined,panel,'chain-meta');
  element('span','链编号',meta,'meta-k'); element('b',currentChain.chain_id,meta).title=currentChain.chain_id;
  element('span',sevCN(currentChain.severity),meta,'alert-sev '+(currentChain.severity||'info'));
  if(card.score!=null){ element('span',('风险分 '+card.score+'/100'),meta,'meta-badge'); }
  const atk=(currentChain.attacker_ips||[]).join('、'), vic=(currentChain.victim_ips||[]).join('、');
  if(atk||vic){ element('span',(atk||'?')+' → '+(vic||'?'),meta,'meta-flow').title='攻击源 → 受害资产'; }
  if(currentChain.correlation_score>0){ element('span','关联分 '+currentChain.correlation_score,meta,'meta-badge').title='关联引擎对这条链内部告警两两判定的平均得分（0~1）'; }
  if(currentChain.campaign_id){const cb=element('span','所属攻击活动 '+(currentChain.campaign_id||'').slice(5,13),meta,'meta-badge campaign-link');cb.title='这条链与其它链被归并为一次跨链攻击活动，点击在"攻击活动"标签页查看全貌';cb.style.cursor='pointer';cb.onclick=()=>{const btn=document.querySelector('[data-tab="campaigns"]');if(btn)btn.click();};}
  const corrReasons=currentChain.correlation_reasons||[];
  if(corrReasons.length){
    const why=element('section',undefined,panel,'detail-section corr-section');
    element('h3','关联依据（这些告警为何被归为一条链）',why);
    const ul=element('ul',undefined,why,'corr-reasons');
    corrReasons.slice(0,8).forEach(r=>{const li=element('li',corrReasonCn(r),ul);li.title=r;});
  }
  const missItems=[...(currentChain.uncertainties||[]).map(uncertaintyCn), ...((currentChain.confidence_card||{}).penalties||[]).map(p=>p.reason)].filter(Boolean);
  if(missItems.length){
    const miss=element('section',undefined,panel,'detail-section corr-section');
    element('h3','缺失证据与不确定项（哪些结论还不满）',miss);
    element('small','确定性校验项已译为中文；英文行保留大模型自述原文（仅作核对用途，不参与打分）。',miss,'corr-note');
    const ul2=element('ul',undefined,miss,'corr-reasons');
    [...new Set(missItems)].slice(0,8).forEach(u=>element('li',u,ul2));
  }
  const viewport=element('div',undefined,panel,'graph-viewport');
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  const stages=currentChain.stages||[]; const boxW=520, gap=112, height=Math.max(170,stages.length*gap+30);
  svg.setAttribute('width','900');svg.setAttribute('height',height);svg.setAttribute('viewBox',`0 0 900 ${height}`);svg.setAttribute('role','img');svg.setAttribute('aria-label','攻击阶段与关系');viewport.append(svg);
  if(!stages.length){element('p','该链摘要已加载，但阶段详情暂不可用。请重新选择本链以按需载入。',panel,'empty-state');return;}
  function shape(tag,attrs,text) {const n=document.createElementNS(svg.namespaceURI,tag);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));if(text!==undefined)n.textContent=text;svg.append(n);return n;}
  const positions=new Map(stages.map((s,i)=>[s.stage_id,{x:40,y:i*gap+22}]));
  const evidence=element('div',undefined,panel,'node-evidence');
  function showStage(stage) {
    evidence.replaceChildren();
    const head=element('div',undefined,evidence,'evidence-head');
    element('b',svgClip('阶段 '+(stages.indexOf(stage)+1)+' · '+attCn(stage.tactic).cn,80),head);
    element('span',attCn(stage.technique).cn+' '+(attCn(stage.technique).code||''),head,'att-line');
    details(evidence,'该阶段说明',{ 战术:attCn(stage.tactic).cn+'（'+(attCn(stage.tactic).code||stage.tactic||'—')+'）',
      技术:attCn(stage.technique).cn+'（'+(attCn(stage.technique).code||stage.technique||'—')+'）',
      置信度:stage.confidence, 时间:(stage.time_range||[]).map(fmtTime).join(' 至 '), 来源:srcCn(stage.source) });
    // —— 从原始数据到判断：命中规则 → 判断结论 → 保留意见 ——
    const basis=element('section',undefined,evidence,'detail-section judge-section');
    element('h3','从原始数据到判断',basis);
    const evRows=(currentTask.bundle?.evidence||[]).filter(e=>(stage.evidence_event_ids||[]).includes(e.event_id)).slice(0,20);
    const rules=[...new Set(evRows.flatMap(e=>e.matched_rules||[]))];
    const step1=element('div',undefined,basis,'judge-step');
    element('b','① 原始数据',step1,'judge-k');
    const chipWrap=element('div',undefined,step1,'judge-chips');
    if(rules.length) rules.forEach(r=>element('span',ruleCn(r),chipWrap,'judge-chip'));
    else element('span','证据行未携带规则标签',chipWrap,'judge-chip');
    element('span',`本阶段 ${evRows.length} 条原始请求（已脱敏，见下方证据）`,step1,'judge-note');
    // 处理前原貌：上传文件中的原始日志行（source_row 锚点；旧产物无此字段自动隐藏）
    const rawRows=evRows.filter(e=>e.source_row!=null||e.request_body||e.user_agent);
    if(rawRows.length){
      const rawBlock=element('div',undefined,step1,'judge-raw');
      element('b','处理前原貌（上传文件中的原始日志）',rawBlock,'judge-raw-t');
      rawRows.slice(0,5).forEach(e=>{
        const file=String(e.source_file||'').split('/').pop().split('\\').pop()||'上传文件';
        const lines=[];
        if(e.source_row!=null) lines.push(`${file} · 第 ${e.source_row} 行`);
        if(e.url_path) lines.push('请求: '+e.url_path);
        if(e.user_agent) lines.push('UA: '+e.user_agent);
        if(e.request_body) lines.push('载荷: '+e.request_body);
        const pre=element('div',undefined,rawBlock,'judge-raw-line');
        lines.forEach(l=>element('div',l,pre));
        if(e.source_row!=null) pre.title=`原始日志锚点：${file} 第 ${e.source_row} 行`;
      });
      if(rawRows.length>5) element('span',`其余 ${rawRows.length-5} 条见下方关联证据`,rawBlock,'judge-note');
    }
    const step2=element('div',undefined,basis,'judge-step');
    element('b','② 得出判断',step2,'judge-k');
    const verdict=element('span',undefined,step2,'judge-verdict'); verdict.innerHTML=attBadge(stage.technique);
    const nar=String(stage.narrative||'').trim();
    if(nar){ const p=element('p',undefined,step2,'judge-narrative'); p.textContent='判断原文：'+nar; p.title=nar; }
    element('span',`来源 ${srcCn(stage.source)} · 置信度 ${stage.confidence}`,step2,'judge-note');
    const techCode=(attCn(stage.technique).code||'').toUpperCase();
    const holds=(currentChain.uncertainties||[]).filter(u=>techCode&&String(u).toUpperCase().includes(techCode)).map(uncertaintyCn);
    if(holds.length){
      const step3=element('div',undefined,basis,'judge-step');
      element('b','③ 保留意见',step3,'judge-k');
      [...new Set(holds)].slice(0,3).forEach(h=>element('p',h,step3,'judge-hold'));
    }
    details(evidence,'关联证据（原始请求，已脱敏）',evRows);
  }
  (currentChain.edges||[]).forEach(([from,to],i)=>{
    const a=positions.get(from),b=positions.get(to); if(!a||!b)return;
    const x=boxW+60+(i%8)*20;
    const connector=shape('path',{d:`M ${boxW+40} ${a.y+42} H ${x} V ${b.y+42} H ${boxW+48}`,fill:'none',stroke:'#6375cf','stroke-width':2});
    shape('path',{d:`M ${boxW+50} ${b.y+37} L ${boxW+40} ${b.y+42} L ${boxW+50} ${b.y+47}`,fill:'none',stroke:'#6375cf','stroke-width':2});
    const fi=stages.findIndex(s=>s.stage_id===from), ti=stages.findIndex(s=>s.stage_id===to);
    const edgeTitle=document.createElementNS(svg.namespaceURI,'title');
    edgeTitle.textContent='阶段 '+(fi+1)+' → 阶段 '+(ti+1)+'：按 ATT&CK 战术推进排序；两阶段因果性由各自证据支撑，仅时间接近不会构成关联（引擎要求同源/同目标/同会话/共享情报等证据）';
    connector.append(edgeTitle);
    // 阶段间时间间隔徽章：让"证据时间跨度"可读（战术序推进≠时间因果）。
    // 只标正间隔；时间重叠（同证据窗，战术序并列）不占版面，语义见悬浮说明。
    const t1=Date.parse(((stages[fi]||{}).time_range||[])[1]||''), t2=Date.parse(((stages[ti]||{}).time_range||[])[0]||'');
    if(!isNaN(t1)&&!isNaN(t2)&&t2>t1){
      const gapSec=Math.round((t2-t1)/1000);
      const label=gapSec>=0?('间隔 '+fmtDuration(gapSec)):'时间重叠';
      const midY=(a.y+b.y)/2+42, bx=x-36;
      const badge=shape('g',{class:'edge-gap-badge'});
      const br=document.createElementNS(svg.namespaceURI,'rect');
      br.setAttribute('x',bx);br.setAttribute('y',midY-11);br.setAttribute('width',72);br.setAttribute('height',22);br.setAttribute('rx',11);
      br.setAttribute('fill','#fff');br.setAttribute('stroke','#c9d6f0');badge.append(br);
      const bt=document.createElementNS(svg.namespaceURI,'text');
      bt.setAttribute('x',bx+36);bt.setAttribute('y',midY+4);bt.setAttribute('font-size','10.5');bt.setAttribute('fill','#5a6a85');bt.setAttribute('text-anchor','middle');bt.setAttribute('pointer-events','none');
      bt.textContent=svgClip(label,13);badge.append(bt);
      const btitle=document.createElementNS(svg.namespaceURI,'title');
      btitle.textContent='相邻两阶段证据时间的间隔（阶段按战术序排列，间隔不代表因果推断）';badge.append(btitle);
    }
  });
  stages.forEach((stage,idx)=>{
    const p=positions.get(stage.stage_id);
    const t=attCn(stage.tactic), te=attCn(stage.technique);
    const g=shape('g',{tabindex:0,role:'button','aria-label':('阶段'+(idx+1)+' '+t.cn+' '+te.cn+' 查看证据')});
    const rect=document.createElementNS(svg.namespaceURI,'rect');
    rect.setAttribute('x',p.x);rect.setAttribute('y',p.y);rect.setAttribute('width',boxW);rect.setAttribute('height',86);
    rect.setAttribute('rx',12);rect.setAttribute('fill','#eef4ff');rect.setAttribute('stroke','#b7c9f2');rect.setAttribute('class','chain-stage-box');
    g.append(rect);
    // 左侧等级色条：一眼看出这条链的整体危险等级（与置信度卡/告警同色语）
    const sevBar=document.createElementNS(svg.namespaceURI,'rect');
    sevBar.setAttribute('x',p.x);sevBar.setAttribute('y',p.y);sevBar.setAttribute('width',6);sevBar.setAttribute('height',86);
    sevBar.setAttribute('rx',3);sevBar.setAttribute('fill',(SEV_HEX[currentChain.severity]||SEV_HEX.info));
    g.append(sevBar);
    const line=(dy,size,txt,fill,weight)=>{const el2=document.createElementNS(svg.namespaceURI,'text');el2.setAttribute('x',p.x+16);el2.setAttribute('y',p.y+dy);el2.setAttribute('font-size',size);el2.setAttribute('fill',fill);el2.setAttribute('font-weight',weight||'400');el2.setAttribute('pointer-events','none');el2.textContent=txt;g.append(el2);};
    line(26,'15','阶段 '+(idx+1)+' · '+svgClip(t.cn,44),'#1b2a52','700');
    line(49,'12.5',svgClip(te.cn,58),'#2c3e66');
    line(71,'11.5','置信度 '+stage.confidence+' · '+(stage.time_range||[]).map(fmtTime).map(x=>x.slice(5)).join(' → '),'#5a6a85');
    g.style.cursor='pointer';
    g.addEventListener('click',()=>showStage(stage));
    g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();showStage(stage);}});
  });
  const controls=element('div',undefined,panel,'chain-actions');let zoom=1;
  [['放大',.2],['缩小',-.2],['复位',0]].forEach(([label,step])=>{element('button',label,controls).onclick=()=>{zoom=step?Math.max(.5,Math.min(2,zoom+step)):1;svg.style.zoom=zoom;};});
  element('small','也可在图上直接滚动缩放、按住拖动平移。',controls,'chain-zoom-tip');
  viewport.addEventListener('wheel',e=>{e.preventDefault();zoom=Math.max(.5,Math.min(2,zoom+(e.deltaY>0?-.1:.1)));svg.style.zoom=zoom;},{passive:false});
  let dragFrom=null;
  viewport.addEventListener('pointerdown',e=>{dragFrom={x:e.clientX,y:e.clientY,l:viewport.scrollLeft,t:viewport.scrollTop};});
  window.addEventListener('pointerup',()=>{dragFrom=null;});
  viewport.addEventListener('pointermove',e=>{if(!dragFrom)return;viewport.scrollLeft=dragFrom.l-(e.clientX-dragFrom.x);viewport.scrollTop=dragFrom.t-(e.clientY-dragFrom.y);});
  element('p','连线表示阶段间的战术推进顺序，每一步的因果性由该阶段证据支撑——仅时间接近的告警不会被系统归入同一条链（引擎要求同源 / 同目标 / 同会话 / 共享情报等证据，异源且无共享情报会被直接否决）。',panel,'panel-intro chain-edge-note');
  if(stages[0])showStage(stages[0]);
};

// 按 ATT&CK 技术给出中文处置建议（与 M2 规则库同源，避免英文正文；未知技术回退通用文案）
const ATT_ADVICE = {
  T1190:['修补被利用的对外服务','证据显示面向公网的应用被漏洞利用。立即修补受影响组件、下线受影响版本，并验证漏洞已不可被外部访问。'],
  T1110:['启用多因子认证与登录限流','观测到重复的认证失败（爆破）。对登录接口强制 MFA、配置账号锁定/频率限制，达到阈值即封禁来源。'],
  T1046:['限制并监控内网探测','检测到服务/端口扫描。做网络分段、限制东西向流量到必要流向，并对扫描特征告警。'],
  T1595:['收敛对外暴露面','观测到对外服务的主动扫描。移除不必要的暴露端口、对入站连接限速，并将扫描源纳入边界封禁。'],
  T1059:['约束命令与脚本解释器','观测到命令解释器活动。限制解释器仅用于授权管理路径，开启脚本块日志，对编码/混淆命令行告警。'],
  T1003:['保护凭据存储','观测到凭据窃取行为。启用凭据防护/LSASS 保护、限制调试权限，并轮换可能已泄露的凭据。'],
  T1021:['收敛远程管理通道','观测到主机间远程服务使用（SMB/RDP/WinRM/SSH）。远程管理仅经跳板机、要求 MFA，并监控横向登录。'],
  T1071:['阻断并检查命令与控制通道','疑似 C2/心跳外联。对已识别的基础设施做 sinkhole/封禁，出口启用 TLS 检查，排查周期性外发。'],
  T1078:['核查账号使用与访问策略','疑似合法账号被滥用。核查涉事账号近期登录、执行最小权限，并轮换来自异常来源的凭据。'],
  T1105:['管控工具与二次载荷入口','观测到工具/载荷传输。限制对外下载、封禁非法文件传输服务，检查代理日志。'],
  T1567:['实施出口数据防泄漏','观测到对外数据传输。启用 DLP/出口过滤、限制上传目的地，对异常流量告警。'],
  T1041:['排查命令与控制外传通道','疑似经 C2 通道外传数据。阻断该通道、留存流量元数据，核实究竟有哪些数据离开了网络。'],
  T1048:['监控备用协议外传','疑似经备用协议（DNS/ICMP 等）外传。强制 DNS 出口管控、检查 ICMP 量、边界限制非法协议。'],
  T1486:['保护备份并准备勒索隔离','观测到加密破坏行为。校验离线备份、隔离受影响主机、停用勒索阶段所用账号。'],
  T1498:['部署大流量拒绝服务防护','观测到网络泛洪。启用上游清洗/限速并阻断涉事来源。'],
  T1082:['监控主机信息探测','观测到系统信息探测。对来自非管理上下文的探测命令告警。'],
  T1547:['审计开机自启持久化位置','观测到自启动/持久化行为。审计受影响主机的自启动键、启动目录与计划任务。'],
  T1562:['保护安全组件免遭破坏','观测到削弱防护的行为。启用防篡改、安全日志异地留存、限制可停用探针的权限。'],
};
function adviceCn(a){
  const code=(a.related_techniques||[])[0]||'';
  const hit=ATT_ADVICE[code];
  if(hit) return {title:hit[0], text:hit[1]};
  // 动态项兜底：Remediate CVE / Block 基础设施 等
  const t=String(a.title||'');
  if(/remediate/i.test(t)&&/cve/i.test(t)) return {title:'修复相关漏洞（CVE）', text:'该链命中已知漏洞，请核对并修补对应 CVE。'};
  if(/block the identified malicious infrastructure/i.test(t)) return {title:'封禁已识别的恶意基础设施', text:'将本次涉及的恶意 IP/域名纳入边界封禁与情报库。'};
  return {title:t||'处置建议', text:a.text||''};
}
function priorityCN(level){return {critical:'立即',high:'高',medium:'常规',low:'观察',info:'参考'}[level]||level||'未标注';}
function actionTrace(action, chains=(currentTask?.chains||[])){
  const wanted=new Set((action.related_techniques||[]).map(x=>String(x).split(' ')[0]));
  const alerts=(currentTask?.alerts||taskAlerts||[]).filter(a=>{
    const codes=[a.technique,a.mitre].filter(Boolean).map(x=>String(x).split(' ')[0]);
    return !wanted.size||codes.some(code=>wanted.has(code));
  });
  const relatedIds=new Set(alerts.map(a=>a.chain_id).filter(Boolean));
  const related=chains.filter(c=>relatedIds.has(c.chain_id)||(!relatedIds.size&&(c.stages||[]).some(s=>wanted.has(String(s.technique||'').split(' ')[0]))));
  const evidence=new Set(alerts.flatMap(a=>a.event_ids||[]));
  related.forEach(c=>(c.stages||[]).forEach(s=>(s.evidence_event_ids||[]).forEach(id=>evidence.add(id))));
  return {related,evidence:[...evidence],top:related[0]};
}
// ATT&CK 编码列表 → 中文（顿号分隔，缺失回退原码）
function attCodes(codes, dict) { return (codes||[]).map(c=>dict[c]||dict[String(c).split(' ')[0]]||c).slice(0,6).join('、')||'—'; }
// 由画像结构化字段生成中文行为概述（与 behavior_summary 同源，避免英文）
function profileSummaryCn(p){
  const parts=[];
  const assets=(p.target_assets||[]).length;
  parts.push(`对 ${assets||'若干'} 个资产发起 ${p.attack_count??'?'} 次攻击`);
  const chains=(p.chain_ids||[]).length; if(chains) parts.push(`横跨 ${chains} 条攻击链`);
  const tac=[...new Set((p.tactics||[]).map(t=>ATT_TACTIC[String(t).split(' ')[0]]||attCn(t).cn))].slice(0,6);
  if(tac.length) parts.push(`涉及战术 ${tac.join('、')}`);
  const te=[...new Set((p.techniques||[]).map(t=>ATT_TECH[String(t).split(' ')[0]]||'').filter(Boolean))].slice(0,5);
  if(te.length) parts.push(`主要手段 ${te.join('、')}`);
  if(p.attribution && p.attribution!=='unknown') parts.push(`疑似归因 ${p.attribution}（置信 ${p.attribution_confidence??'低'}）`);
  return parts.join('；')+'。';
}
// 把 M2 的英文 risk_reason（如 "highest-impact tactic: TA0010 (Exfiltration)"）转成中文
function riskReasonCn(raw){
  let s=String(raw||'').trim();
  if(!s) return '暂无风险原因';
  const map={'highest-impact tactic':'最高危战术','multiple stages in one chain':'单链多阶段行为','suspicious event':'可疑事件','rule signature':'规则命中'};
  for(const [en,zh] of Object.entries(map)) s=s.replace(new RegExp(en,'gi'),zh);
  s=s.replace(/(T[A-Z]?\d+(?:\.\d+)?)\s*\(([^)]+)\)/g,(m,code,en)=>`${ATT_TACTIC[code]||ATT_TECH[code]||en}（${code}）`);
  s=s.replace(/\b(TA?\d{4}(?:\.\d+)?)\b/g,(m,c)=>ATT_TACTIC[c]||ATT_TECH[c]||c);
  return s;
}
const chainSearchInput=document.querySelector('#chain-search');
const chainSearchCount=document.querySelector('#chain-search-count');
function populateChainSelector(query=chainSearchInput?.value||'') {
  const sorted=sortChains(currentTask?.chains||[]);
  const ranks=new Map(sorted.map((chain,index)=>[chain.chain_id,index+1]));
  const q=String(query||'').trim().toLowerCase();
  const matches=q ? sorted.filter(c=>[
    c.chain_id,c.severity,c.attacker_ips,c.victim_ips,c.attack_types,c.techniques
  ].flat(Infinity).some(value=>String(value||'').toLowerCase().includes(q))) : sorted;
  const multiAll=matches.filter(c=>(c.stage_count??c.stages?.length??0)>1);
  const singleAll=matches.filter(c=>(c.stage_count??c.stages?.length??0)<=1);
  const visible=q ? matches.slice(0,300) : multiAll.concat(singleAll.slice(0,160));
  const selectedId=currentChain?.chain_id;
  const selected=selectedId && sorted.find(c=>c.chain_id===selectedId);
  const selectedWasAdded=Boolean(selected && !visible.some(c=>c.chain_id===selectedId));
  if(selectedWasAdded) visible.unshift(selected);

  chainSelector.replaceChildren();
  const currentGroup=element('optgroup',undefined,chainSelector);currentGroup.label='当前查看';
  const multi=element('optgroup',undefined,chainSelector);multi.label='多阶段攻击链（优先）';
  const single=element('optgroup',undefined,chainSelector);single.label='单阶段攻击链（按风险排序）';
  visible.forEach(c=>{
    const count=c.stage_count??c.stages?.length??0;
    const parent=c.chain_id===selectedId&&selectedWasAdded?currentGroup:(count>1?multi:single);
    const option=element('option',
      `#${ranks.get(c.chain_id)||'?'} ${count||'?'}阶段 · ${sevCN(c.severity)} · 风险分 ${c.confidence_card?.score ?? c.risk_score ?? '?'} · ${(c.attacker_ips?.[0]||'?')} → ${(c.victim_ips?.[0]||'?')}`,
      parent);
    option.value=c.chain_id;
  });
  [currentGroup,multi,single].forEach(group=>{if(!group.children.length)group.remove();});
  if(!visible.length){const option=element('option','没有匹配的攻击链',chainSelector);option.disabled=true;}
  if(selectedId) chainSelector.value=selectedId;
  chainSelector.disabled=!visible.length;
  if(chainSearchCount) chainSearchCount.textContent=q
    ? `匹配 ${matches.length} 条${matches.length>300?'，显示前 300 条':''}${selectedWasAdded?'；另保留当前链':''}`
    : `共 ${sorted.length} 条；优先显示 ${multiAll.length} 条多阶段链和前 ${Math.min(singleAll.length,160)} 条高风险单阶段链${selectedWasAdded?'；另保留当前链':''}`;
}
if(chainSearchInput) chainSearchInput.addEventListener('input',()=>populateChainSelector());

// —— 攻击活动实体关系图（主流"实体图"语汇的轻量版：攻击源 | 链 | 受害资产 三列二部图） ——
async function openChainById(id) {
  currentChain=await api('/attack-chains/'+encodeURIComponent(id));
  populateChainSelector(); renderChain();
  const pb=document.querySelector('[data-tab="path"]'); if(pb)pb.click();
}
function campaignGraph(cp, host, chainById) {
  const all=(cp.members||[]);
  const chains=all.slice(0,12), extraChains=all.length-chains.length;
  const attackers=(cp.attacker_ips||[]).slice(0,6), victims=(cp.victim_ips||[]).slice(0,6);
  const svgNS='http://www.w3.org/2000/svg';
  const rowH=40, W=860;
  const rows=Math.max(chains.length, attackers.length, victims.length, 2);
  const H=rows*rowH+34;
  const wrap=element('div',undefined,host,'graph-viewport campaign-graph');
  const svg=document.createElementNS(svgNS,'svg');
  svg.setAttribute('width',W);svg.setAttribute('height',H);svg.setAttribute('viewBox',`0 0 ${W} ${H}`);
  svg.setAttribute('role','img');svg.setAttribute('aria-label','攻击活动实体关系图');wrap.append(svg);
  const mk=(tag,attrs,text,parent)=>{const n=document.createElementNS(svgNS,tag);Object.entries(attrs).forEach(([k,v])=>n.setAttribute(k,v));if(text!==undefined)n.textContent=text;(parent||svg).append(n);return n;};
  const col={a:16,aw:180, c:300,cw:250, v:664,vw:180};
  const chainY=i=>i*rowH+24, sideY=i=>i*rowH+24;
  const chainMid=(chainY(0)+chainY(Math.max(chains.length-1,0))+30)/2;
  const srcNodes=attackers.length?attackers.map((ip,i)=>({label:ip,y:sideY(i)})):[{label:'来源未提供',y:chainMid-15,ph:true}];
  const vicNodes=victims.length?victims.map((ip,i)=>({label:ip,y:sideY(i)})):[{label:'目标未提供',y:chainMid-15,ph:true}];
  mk('text',{x:col.a+8,y:12,'font-size':11,fill:'#5d6b84','font-weight':'600'},'攻击源');
  mk('text',{x:col.c+8,y:12,'font-size':11,fill:'#5d6b84','font-weight':'600'},'攻击链（按时间）');
  mk('text',{x:col.v+8,y:12,'font-size':11,fill:'#5d6b84','font-weight':'600'},'受害资产');
  // 边：谁发起这条链 / 这条链打了谁（成员链的实体归属取自 bundle chains，缺省用占位节点）
  chains.forEach((m,i)=>{
    const y=chainY(i)+15;
    const full=chainById.get(m.chain_id);
    const srcs=(full&&full.attacker_ips&&full.attacker_ips.length)?full.attacker_ips.slice(0,3):[];
    const tcts=(full&&full.victim_ips&&full.victim_ips.length)?full.victim_ips.slice(0,3):[];
    (srcs.length?srcs:[{__ph:true}]).forEach(s=>{
      const node=s.__ph?srcNodes.find(n=>n.ph):srcNodes.find(n=>n.label===s);
      if(!node)return;
      const edge=mk('line',{x1:col.a+col.aw,y1:node.y+15,x2:col.c,y2:y,stroke:'#b9c6e8','stroke-width':1.5,opacity:.85});
      const t=document.createElementNS(svgNS,'title');t.textContent='链 '+m.chain_id+' 由攻击源 '+(s.__ph?'（未提供）':s)+' 发起';edge.append(t);
    });
    (tcts.length?tcts:[{__ph:true}]).forEach(v=>{
      const node=v.__ph?vicNodes.find(n=>n.ph):vicNodes.find(n=>n.label===v);
      if(!node)return;
      const edge=mk('line',{x1:col.c+col.cw,y1:y,x2:col.v,y2:node.y+15,stroke:'#b9c6e8','stroke-width':1.5,opacity:.85});
      const t=document.createElementNS(svgNS,'title');t.textContent='链 '+m.chain_id+' 命中资产 '+(v.__ph?'（未提供）':v);edge.append(t);
    });
  });
  // 节点：攻击源
  srcNodes.forEach(n=>{
    mk('rect',{x:col.a,y:n.y,width:col.aw,height:30,rx:8,fill:n.ph?'#f7f9fc':'#fff7ef',stroke:n.ph?'#b6c2d8':'#eab24a','stroke-dasharray':n.ph?'4 3':'none'});
    const t=document.createElementNS(svgNS,'text');t.setAttribute('x',col.a+10);t.setAttribute('y',n.y+19);t.setAttribute('font-size',12);t.setAttribute('fill',n.ph?'#8a94a8':'#8a5a12');t.setAttribute('font-weight','600');t.textContent=svgClip(n.label,18);svg.append(t);
  });
  // 节点：受害资产
  vicNodes.forEach(n=>{
    mk('rect',{x:col.v,y:n.y,width:col.vw,height:30,rx:8,fill:n.ph?'#f7f9fc':'#eff6ff',stroke:n.ph?'#b6c2d8':'#7fa7e8','stroke-dasharray':n.ph?'4 3':'none'});
    const t=document.createElementNS(svgNS,'text');t.setAttribute('x',col.v+10);t.setAttribute('y',n.y+19);t.setAttribute('font-size',12);t.setAttribute('fill',n.ph?'#8a94a8':'#2b4c86');t.setAttribute('font-weight','600');t.textContent=svgClip(n.label,18);svg.append(t);
  });
  // 节点：链芯片（可点击）
  chains.forEach((m,i)=>{
    const y=chainY(i);
    const g=mk('g',{class:'camp-node linked',tabindex:0,role:'button','aria-label':'查看链 '+m.chain_id});
    mk('rect',{x:col.c,y,width:col.cw,height:30,rx:8,fill:'#eef4ff',stroke:SEV_HEX[m.severity]||SEV_HEX.info,'stroke-width':1.5},undefined,g);
    mk('circle',{cx:col.c+12,cy:y+15,r:4,fill:SEV_HEX[m.severity]||SEV_HEX.info},undefined,g);
    const t=document.createElementNS(svgNS,'text');
    t.setAttribute('x',col.c+22);t.setAttribute('y',y+19);t.setAttribute('font-size',11.5);t.setAttribute('fill','#263650');t.setAttribute('pointer-events','none');
    t.textContent=svgClip(m.chain_id,17)+' · '+((m.risk_score==null?'—':m.risk_score)+'分');
    g.append(t);
    const sub=document.createElementNS(svgNS,'title');sub.textContent=m.chain_id+' · '+sevCN(m.severity)+' · 点击查看路径图与证据';g.append(sub);
    g.style.cursor='pointer';
    g.addEventListener('click',()=>openChainById(m.chain_id));
    g.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();openChainById(m.chain_id);}});
  });
  if(extraChains>0) element('small','…另有 '+extraChains+' 条成员链未画入图（详见下方成员列表）。',host,'panel-intro');
}

// —— 任务级关联图（NetworkX 后端建图：坐标/社区/中心性预计算，前端渲染并保留全部交互） ——
const GRAPH_PALETTE = ['#dbe7ff', '#dff3ea', '#fdeee0', '#f3e6fb', '#e0f4f7', '#fbe3e6'];
function renderTaskGraph(b, host) {
  const g=b.graph;
  element('p','这张图由 NetworkX 在后端建图：节点=攻击源 / 受害资产 / 攻击链，边=发起 / 命中 / 战役归并；底色相同的节点是社区发现聚出的同一活动簇。节点可拖拽、滚轮缩放、悬浮高亮关联边；点击链节点跳转路径图，点击 IP 展开它涉及的链。',host,'panel-intro');
  if(!g||!g.nodes||!g.nodes.length){ element('p','本任务结果包未包含关联图（重新分析后生成）；下方"攻击活动"页仍有战役归并明细。',host,'empty-state'); return; }
  const st=g.stats||{};
  // —— 聚焦视图：下拉选择独立链/战役，只看局部三列图；全景保留 ——
  const focusBar=element('div',undefined,host,'graph-focus-bar');
  element('span','聚焦视图',focusBar,'graph-focus-label');
  const focusSel=element('select',undefined,focusBar,'graph-focus');
  focusSel.setAttribute('aria-label','聚焦到某条独立链或某个战役');
  const focusWrap=element('div',undefined,host,'task-graph-focus');
  const chainById=new Map([...(currentTask.chains||[]), ...(b.chains||[])].map(c=>[c.chain_id,c]));
  const graphChains=(g.nodes||[]).filter(n=>n.type==='chain');
  const campIds=[...new Set(graphChains.map(n=>n.campaign_id).filter(Boolean))];
  const focusCamps=(b.campaigns||[]).filter(c=>campIds.includes(c.campaign_id))
    .sort((x,y)=>(y.chain_count||0)-(x.chain_count||0));
  const soloChains=graphChains.filter(n=>!n.campaign_id)
    .sort((x,y)=>(y.risk_score||0)-(x.risk_score||0));
  const addOpt=(val,text)=>{const o=document.createElement('option');o.value=val;o.textContent=text;focusSel.append(o);};
  addOpt('all','全景 · 全部节点（'+st.node_count+'）');
  focusCamps.forEach(cp=>addOpt('camp:'+cp.campaign_id,
    '战役 '+(cp.campaign_id||'').slice(5,13)+' · '+(cp.chain_count||0)+' 链 · '+(cp.attacker_ips||[]).slice(0,1).join('')+' → '+(cp.victim_ips||[]).slice(0,1).join('')));
  soloChains.forEach(n=>addOpt('chain:'+n.chain_id,
    '独立链 '+n.label+' · 风险 '+(n.risk_score==null?'—':n.risk_score)+' · '+(n.stage_count||0)+' 阶段'));
  function renderFocus(){
    const v=focusSel.value;
    focusWrap.replaceChildren();
    if(v==='all'){ renderFull(); return; }
    if(v.indexOf('camp:')===0){
      const cp=(b.campaigns||[]).find(c=>'camp:'+c.campaign_id===v);
      if(!cp){ element('p','该战役数据不可用。',focusWrap,'empty-state'); return; }
      const card=element('div',undefined,focusWrap,'campaign-card');
      campaignGraph(cp, card, chainById);
      if(cp.reasons&&cp.reasons.length){
        const why=element('div',undefined,card,'campaign-why');
        element('b','归并依据：',why);
        const ul=element('ul',undefined,why,'corr-reasons');
        cp.reasons.slice(0,6).forEach(r=>element('li',r,ul));
      }
      return;
    }
    const cid=v.slice(6);
    const n=graphChains.find(x=>x.chain_id===cid);
    if(!n){ element('p','该链数据不可用。',focusWrap,'empty-state'); return; }
    const edges=g.edges||[];
    const atts=[...new Set(edges.filter(e=>e.target===cid&&e.type==='launches').map(e=>e.source.replace(/^ip:/,'')))];
    const vics=[...new Set(edges.filter(e=>e.source===cid&&e.type==='targets').map(e=>e.target.replace(/^ip:/,'')))];
    const fake={campaign_id:'solo-'+cid, members:[{chain_id:cid, severity:n.severity, risk_score:n.risk_score,
      stage_count:n.stage_count, first_seen:n.first_seen, last_seen:n.last_seen}],
      attacker_ips:atts, victim_ips:vics, reasons:[]};
    const card=element('div',undefined,focusWrap,'campaign-card');
    element('small','这是独立链的局部视图：'+(atts.length?atts.join('、'):'来源未提供')+' → '+cid+(vics.length?(' → '+vics.join('、')):'')+'。完整证据点击链芯片进入路径图。',card,'campaign-times');
    campaignGraph(fake, card, chainById);
  }
  focusSel.onchange=renderFocus;
  function renderFull() {
  const statsBar=element('div',undefined,focusWrap,'graph-stats');
  [['节点',st.node_count],['边',st.edge_count],['连通簇',st.component_count],['社区',st.community_count]].forEach(([k,v])=>{const c=element('span',undefined,statsBar,'graph-stat');element('small',k,c);element('b',String(v??'—'),c);});
  if(g.note){ element('small',g.note,statsBar,'graph-note').title='大规模任务的截断策略：保证图可读，完整链仍走链选择器'; }
  const legend=element('div',undefined,focusWrap,'graph-legend');
  const lgChip=element('span',undefined,legend,'lg-item'); element('i',undefined,lgChip,'lg-sw lg-chain'); element('small','链节点（描边=危险等级，底色=社区）',lgChip);
  const lgA=element('span',undefined,legend,'lg-item'); element('i',undefined,lgA,'lg-sw lg-att'); element('small','攻击源',lgA);
  const lgV=element('span',undefined,legend,'lg-item'); element('i',undefined,lgV,'lg-sw lg-vic'); element('small','受害资产',lgV);
  const lgE=element('span',undefined,legend,'lg-item'); element('i',undefined,lgE,'lg-line'); element('small','发起 / 命中',lgE);
  const lgC=element('span',undefined,legend,'lg-item'); element('i',undefined,lgC,'lg-line lg-camp'); element('small','战役归并',lgC);

  const W=(g.canvas&&g.canvas.width)||900, H=(g.canvas&&g.canvas.height)||600;
  const wrap=element('div',undefined,focusWrap,'graph-viewport task-graph');
  wrap.style.maxWidth=(W+24)+'px';
  const svgNS='http://www.w3.org/2000/svg';
  const svg=document.createElementNS(svgNS,'svg');
  svg.setAttribute('width',W);svg.setAttribute('height',H);svg.setAttribute('viewBox','0 0 '+W+' '+H);
  svg.setAttribute('role','img');svg.setAttribute('aria-label','任务关联图');wrap.append(svg);
  const defs=document.createElementNS(svgNS,'defs');svg.append(defs);
  const marker=document.createElementNS(svgNS,'marker');
  marker.setAttribute('id','graph-arrow');marker.setAttribute('viewBox','0 0 10 10');
  marker.setAttribute('refX','8.5');marker.setAttribute('refY','5');marker.setAttribute('markerWidth','6.5');marker.setAttribute('markerHeight','6.5');marker.setAttribute('orient','auto-start-reverse');
  const mp=document.createElementNS(svgNS,'path');mp.setAttribute('d','M 0 1 L 9 5 L 0 9 z');mp.setAttribute('fill','#8fa3c8');marker.append(mp);defs.append(marker);
  const dots=document.createElementNS(svgNS,'pattern');
  dots.setAttribute('id','dotgrid');dots.setAttribute('width','22');dots.setAttribute('height','22');dots.setAttribute('patternUnits','userSpaceOnUse');
  const dot=document.createElementNS(svgNS,'circle');dot.setAttribute('cx','1.4');dot.setAttribute('cy','1.4');dot.setAttribute('r','1.2');dot.setAttribute('fill','#dbe4f3');
  dots.append(dot);defs.append(dots);
  const bg=document.createElementNS(svgNS,'rect');
  bg.setAttribute('x',0);bg.setAttribute('y',0);bg.setAttribute('width',W);bg.setAttribute('height',H);
  bg.setAttribute('fill','url(#dotgrid)');bg.setAttribute('rx',12);
  svg.append(bg);
  const nodeById=new Map((g.nodes||[]).map(n=>[n.id,n]));
  const HALF={chain:[63,22], ip:[56,17]};
  const edgeEls=[], nodeEls=new Map();
  const fmtGap=s=>s>=60?fmtDuration(s):(s+' 秒');
  function trim(sx,sy,tx,ty,hs,ht){
    const dx=tx-sx, dy=ty-sy, len=Math.hypot(dx,dy)||1;
    const ux=dx/len, uy=dy/len;
    const off=(half)=>Math.min(half[0]/Math.abs(ux||1e-9), half[1]/Math.abs(uy||1e-9))+3;
    return [sx+ux*off(hs), sy+uy*off(hs), tx-ux*off(ht), ty-uy*off(ht)];
  }
  function relayoutEdge(rec){
    const s=nodeById.get(rec.s), t=nodeById.get(rec.t); if(!s||!t)return;
    const pts=trim(s.x,s.y,t.x,t.y,HALF[s.type]||HALF.chain,HALF[t.type]||HALF.chain);
    rec.el.setAttribute('x1',pts[0]);rec.el.setAttribute('y1',pts[1]);
    rec.el.setAttribute('x2',pts[2]);rec.el.setAttribute('y2',pts[3]);
  }
  function drawEdge(e) {
    const s=nodeById.get(e.source), t=nodeById.get(e.target); if(!s||!t)return;
    const line=document.createElementNS(svgNS,'line');
    line.setAttribute('stroke',e.type==='campaign'?'#e0a05a':'#aebfe2');
    line.setAttribute('stroke-width',e.type==='campaign'?2:1.6);
    if(e.type==='campaign')line.setAttribute('stroke-dasharray','6 4');
    line.setAttribute('marker-end','url(#graph-arrow)');
    line.setAttribute('class','graph-edge');
    const title=document.createElementNS(svgNS,'title');
    title.textContent=(e.reason||e.type)+((e.gap_seconds!=null)?(' · 间隔 '+fmtGap(e.gap_seconds)):'');
    line.append(title); svg.append(line);
    const rec={el:line,s:e.source,t:e.target};
    relayoutEdge(rec); edgeEls.push(rec);
  }
  function drawNode(n) {
    const gEl=document.createElementNS(svgNS,'g');
    gEl.setAttribute('class','graph-node');gEl.setAttribute('tabindex','0');gEl.setAttribute('role','button');
    gEl.setAttribute('transform','translate('+n.x+','+n.y+')');
    // 垫层矩形当静态投影（CSS drop-shadow 在 260+ 节点下会拖垮合成）
    const sh=document.createElementNS(svgNS,'rect');
    const shW=n.type==='chain'?126:112, shH=n.type==='chain'?44:34, shX=n.type==='chain'?-61.5:-54.5, shY=n.type==='chain'?-20:-15;
    sh.setAttribute('x',shX+2);sh.setAttribute('y',shY+3);sh.setAttribute('width',shW);sh.setAttribute('height',shH);sh.setAttribute('rx',n.type==='chain'?10:9);
    sh.setAttribute('fill','rgba(23,35,60,.10)');
    gEl.append(sh);
    if(n.type==='chain'){
      gEl.setAttribute('aria-label','链 '+n.label+' 查看路径图');
      const r=document.createElementNS(svgNS,'rect');
      r.setAttribute('x',-63);r.setAttribute('y',-22);r.setAttribute('width',126);r.setAttribute('height',44);r.setAttribute('rx',10);
      r.setAttribute('fill',GRAPH_PALETTE[(n.community??0)%GRAPH_PALETTE.length]);
      r.setAttribute('stroke',SEV_HEX[n.severity]||SEV_HEX.info);r.setAttribute('stroke-width','2.2');
      gEl.append(r);
      const dotC=document.createElementNS(svgNS,'circle');
      dotC.setAttribute('cx',-45);dotC.setAttribute('cy',0);dotC.setAttribute('r',5);
      dotC.setAttribute('fill',SEV_HEX[n.severity]||SEV_HEX.info);
      gEl.append(dotC);
      const t1=document.createElementNS(svgNS,'text');
      t1.setAttribute('x',-33);t1.setAttribute('y',-4);t1.setAttribute('font-size','11');t1.setAttribute('font-weight','700');t1.setAttribute('fill','#263650');
      t1.textContent=svgClip(n.label,15);gEl.append(t1);
      const t2=document.createElementNS(svgNS,'text');
      t2.setAttribute('x',-33);t2.setAttribute('y',11);t2.setAttribute('font-size','10');t2.setAttribute('fill','#5d6b84');
      t2.textContent='风险 '+(n.risk_score==null?'—':n.risk_score)+' · '+(n.stage_count||0)+' 阶段';gEl.append(t2);
      const title=document.createElementNS(svgNS,'title');
      title.textContent='攻击链 '+n.chain_id+' · '+sevCN(n.severity)+' · 风险分 '+(n.risk_score??'—')+' · '+(n.stage_count||0)+' 阶段'+(n.campaign_id?(' · 属于活动 '+n.campaign_id):'')+' · 点击查看路径图';
      gEl.append(title);
    } else {
      const isAtt=(n.roles||[]).includes('attacker'), isVic=(n.roles||[]).includes('victim');
      gEl.setAttribute('aria-label','IP '+n.label);
      const r=document.createElementNS(svgNS,'rect');
      r.setAttribute('x',-56);r.setAttribute('y',-17);r.setAttribute('width',112);r.setAttribute('height',34);r.setAttribute('rx',9);
      r.setAttribute('fill',isAtt&&isVic?'#f3e6fb':isAtt?'#fff3e2':'#e9f3ff');
      r.setAttribute('stroke',isAtt&&isVic?'#a78bfa':isAtt?'#eab24a':'#7fa7e8');r.setAttribute('stroke-width','1.8');
      gEl.append(r);
      const t=document.createElementNS(svgNS,'text');
      t.setAttribute('x',0);t.setAttribute('y',4.5);t.setAttribute('font-size','11.5');t.setAttribute('font-weight','700');
      t.setAttribute('text-anchor','middle');t.setAttribute('fill',isAtt&&isVic?'#6d3fb0':isAtt?'#8a5a12':'#2b4c86');
      t.textContent=svgClip(n.label,15);gEl.append(t);
      const title=document.createElementNS(svgNS,'title');
      title.textContent=(isAtt&&isVic?'攻击源+受害资产':isAtt?'攻击源':'受害资产')+' '+n.label+' · 关联 '+(n.degree||0)+' 条边 · 点击查看涉及的链';
      gEl.append(title);
    }
    gEl.style.cursor='pointer';
    svg.append(gEl);
    nodeEls.set(n.id,{el:gEl,node:n});
    return gEl;
  }
  (g.edges||[]).forEach(drawEdge);
  (g.nodes||[]).forEach(drawNode);
  function highlight(id) {
    edgeEls.forEach(rec=>{
      const on=!id||rec.s===id||rec.t===id;
      rec.el.style.opacity=on?'1':'0.18';
    });
    nodeEls.forEach((entry,nid)=>{
      const neighbor=!id||nid===id||edgeEls.some(rec=>(rec.s===id&&rec.t===nid)||(rec.t===id&&rec.s===nid));
      entry.el.style.opacity=neighbor?'1':'0.28';
    });
  }
  const info=element('div',undefined,focusWrap,'task-graph-info');
  element('span','点击 IP 节点后，这里会列出它涉及的攻击链。',info,'graph-info-hint');
  function showIp(n) {
    info.replaceChildren();
    const isAtt=(n.roles||[]).includes('attacker'), isVic=(n.roles||[]).includes('victim');
    element('b',(isAtt&&isVic?'攻击源 + 受害资产':isAtt?'攻击源':'受害资产')+' '+n.label+' · 关联 '+(n.degree||0)+' 条边',info);
    const list=element('ul',undefined,info,'corr-reasons');
    (g.edges||[]).filter(e=>e.source==='ip:'+n.label||e.target==='ip:'+n.label).forEach(e=>{
      const otherId=e.source==='ip:'+n.label?e.target:e.source;
      const other=nodeById.get(otherId);
      if(other&&other.type==='chain'){
        const li=element('li',svgClip(other.label,16)+' · '+(other.risk_score??'—')+' 分 · ',list);
        const btn=element('button','查看链',li,'trace-btn');
        btn.onclick=()=>openChainById(other.chain_id);
      }
    });
    if(!list.children.length) element('li','（无可展开的链）',list);
  }
  nodeEls.forEach((entry)=>{
    const node=entry.node, el=entry.el;
    el.addEventListener('pointerenter',()=>highlight(node.id));
    el.addEventListener('pointerleave',()=>highlight(null));
    let drag=null;
    el.addEventListener('pointerdown',e=>{
      drag={sx:e.clientX,sy:e.clientY,ox:node.x,oy:node.y,moved:false};
      el.setPointerCapture&&el.setPointerCapture(e.pointerId);
      e.preventDefault();
    });
    el.addEventListener('pointermove',e=>{
      if(!drag)return;
      const dx=e.clientX-drag.sx, dy=e.clientY-drag.sy;
      if(Math.abs(dx)+Math.abs(dy)>3)drag.moved=true;
      if(!drag.moved)return;
      node.x=drag.ox+dx; node.y=drag.oy+dy;
      el.setAttribute('transform','translate('+node.x+','+node.y+')');
      edgeEls.forEach(rec=>{ if(rec.s===node.id||rec.t===node.id) relayoutEdge(rec); });
    });
    el.addEventListener('pointerup',e=>{
      const wasDrag=drag&&drag.moved; drag=null;
      if(wasDrag)return;
      if(node.type==='chain')openChainById(node.chain_id); else showIp(node);
    });
    el.addEventListener('keydown',ev=>{if(ev.key==='Enter'||ev.key===' '){ev.preventDefault();node.type==='chain'?openChainById(node.chain_id):showIp(node);}});
  });
  let zoom=1;
  wrap.addEventListener('wheel',ev=>{ev.preventDefault();zoom=Math.max(.5,Math.min(2.5,zoom+(ev.deltaY>0?-.1:.1)));svg.style.zoom=zoom;},{passive:false});
  let pan=null;
  wrap.addEventListener('pointerdown',ev=>{if(ev.target!==bg)return;pan={x:ev.clientX,y:ev.clientY,l:wrap.scrollLeft,t:wrap.scrollTop};});
  window.addEventListener('pointerup',()=>{pan=null;});
  wrap.addEventListener('pointermove',ev=>{if(!pan)return;wrap.scrollLeft=pan.l-(ev.clientX-pan.x);wrap.scrollTop=pan.t-(ev.clientY-pan.y);});
  }
  renderFocus();
}

renderBundle=function() {
  const sorted=sortChains(currentTask.chains||[]);
  populateChainSelector();
  const b=currentTask.bundle; if(!b) return;
  const tab=id=>document.getElementById(id);

  // —— ② 关联图：NetworkX 建图（后端算坐标/社区，前端渲染保留交互） ——
  const gph=tab('tab-graph'); if(gph){ gph.replaceChildren(); renderTaskGraph(b, gph); }

  // —— ③ 攻击活动：跨链归并视图（同源/同目标 + 时间相容才合并，理由逐条落档） ——
  const camp=tab('tab-campaigns'); if(camp){ camp.replaceChildren();
    element('p','「攻击活动」把多条攻击链归并成一次完整行动：同一来源反复进攻，或多个来源协同打击同一资产。上方实体图展示"哪个来源 → 哪些链 → 打了哪些资产"，每条归并都给出理由；互相独立的链不在此页列出（它们可在上方链选择器单独查看）。',camp,'panel-intro');
    const camps=(b.campaigns||[]).slice().sort((x,y)=>(SEV_ORDER[x.severity]??9)-(SEV_ORDER[y.severity]??9)||(y.chain_count||0)-(x.chain_count||0));
    if(!camps.length){ element('p','本任务没有发现跨链攻击活动（各链相互独立）。',camp,'empty-state'); }
    // 每条链的攻击源/受害归属：详情接口剥离了 bundle.chains，用任务顶层全量 chains 兜底
    const chainById=new Map([...(currentTask.chains||[]), ...(b.chains||[])].map(c=>[c.chain_id,c]));
    camps.forEach(cp=>{
      const card=element('div',undefined,camp,'campaign-card');
      const head=element('div',undefined,card,'campaign-head');
      element('b',cp.campaign_id,head).title=cp.campaign_id;
      element('span',sevCN(cp.severity),head,'alert-sev '+(cp.severity||'info'));
      element('span',(cp.chain_count||0)+' 条链',head,'meta-badge');
      if(cp.multistage_count){ element('span','多阶段 '+cp.multistage_count,head,'meta-badge'); }
      const src=(cp.attacker_ips||[]).join('、')||'来源未提供', tgt=(cp.victim_ips||[]).join('、')||'目标未提供';
      element('span',src+' → '+tgt,head,'meta-flow').title='攻击源 → 受害资产';
      element('small','时间跨度 '+(cp.first_seen?fmtTime(cp.first_seen):'—')+' 至 '+(cp.last_seen?fmtTime(cp.last_seen):'—')+' · 主要战术 '+attCodes(cp.top_tactics,ATT_TACTIC),card,'campaign-times');
      campaignGraph(cp, card, chainById);
      if(cp.reasons&&cp.reasons.length){
        const why=element('div',undefined,card,'campaign-why');
        element('b','归并依据：',why);
        const ul=element('ul',undefined,why,'corr-reasons');
        cp.reasons.slice(0,6).forEach(r=>element('li',r,ul));
      }
      const members=element('div',undefined,card,'campaign-members');
      (cp.members||[]).slice(0,20).forEach(m=>{
        const row=element('div',undefined,members,'campaign-member');
        element('span',m.chain_id,row,'campaign-chain-id');
        element('span',sevCN(m.severity),row,'alert-sev '+(m.severity||'info'));
        element('span',((m.risk_score==null?'—':m.risk_score)+'/100 分 · '+(m.stage_count||0)+' 阶段 · '+(m.first_seen?fmtTime(m.first_seen):'—')),row,'campaign-member-meta');
        const open=element('button','查看链',row,'trace-btn');
        open.onclick=async()=>{ currentChain=await api('/attack-chains/'+encodeURIComponent(m.chain_id)); populateChainSelector(); renderChain(); const pb=document.querySelector('[data-tab="path"]'); if(pb)pb.click(); };
      });
      if((cp.members||[]).length>20) element('small','…其余 '+(cp.members.length-20)+' 条成员链可在攻击链页搜索链编号查看。',members,'panel-intro');
    });
  }

  // —— ④ 攻击者画像：紧凑表格，不再铺 JSON 卡 ——
  const prof=tab('tab-profiles'); if(prof){ prof.replaceChildren();
    element('p','每个"攻击者画像"聚合同一来源 IP 的全部行为：打了谁、打了几次、用了哪些手段、是否已被其他链共用。',prof,'panel-intro');
    const list=(b.profiles||[]).slice().sort((x,y)=>(y.attack_count||0)-(x.attack_count||0));
    if(!list.length){ element('p','暂无攻击者画像。',prof); }
    else {
      const wrap=element('div',undefined,prof,'table-scroll');
      const table=element('table',undefined,wrap,'data-table');
      const thead=element('thead',undefined,table); const hr=element('tr',undefined,thead);
      ['攻击源 IP','攻击次数','最高等级','关联攻击链','主要战术','受害资产数','行为概述'].forEach(h=>element('th',h,hr));
      const tbody=element('tbody',undefined,table);
      list.forEach(p=>{
        const tr=element('tr',undefined,tbody);
        element('td',(p.attacker_ips||[]).join('、')||p.profile_id||'—',tr).style.fontWeight='600';
        element('td',String(p.attack_count??'—'),tr).style.textAlign='right';
        const tdSev=element('td','',tr); element('span',sevCN(p.max_severity),tdSev,'alert-sev '+(p.max_severity||'info'));
        element('td',String((p.chain_ids||[]).length||'—'),tr).style.textAlign='right';
        element('td',attCodes(p.tactics,ATT_TACTIC),tr).title=(p.tactics||[]).join(', ');
        element('td',String((p.target_assets||[]).length||'—'),tr).style.textAlign='right';
        const sum=profileSummaryCn(p); element('td',svgClip(sum,72),tr).title=sum;
      });
    }
  }

  // —— ⑤ 处置建议：列表 ——
  const act=tab('tab-actions'); if(act){ act.replaceChildren();
    element('p','按优先级排序的处置建议。每条标注依据来源，方便核对是规则命中还是模型判断。',act,'panel-intro');
    const actions=sortActions(b.report.recommended_actions||[]);
    if(!actions.length) element('p','暂无处置建议。',act);
    actions.forEach((a,i)=>{
      const row=element('div',undefined,act,'action-row');
      element('span',String(i+1),row,'action-idx');
      const body=element('div',undefined,row,'action-body');
      const adv=adviceCn(a);
      element('b',adv.title,body);
      element('p',adv.text||'',body);
      const trace=actionTrace(a,currentChain?[currentChain]:[]);
      element('small','为什么：'+(a.related_techniques?.length?'当前链观测到 '+attCodes(a.related_techniques,ATT_TECH):'基于本次链路的通用防护要求')+' · '+trace.evidence.length+' 条证据可追溯',body);
      element('small','处置优先级 '+priorityCN(a.priority)+' · 来源 '+srcCn(a.source),body);
      if(trace.top){const open=element('button','查看关联证据',body,'trace-btn');open.onclick=()=>{currentChain=trace.top;populateChainSelector();renderChain();document.querySelector('[data-tab="path"]').click();};}
    });
  }

  // —— ⑥ 证据与统计：报告摘要 + 指标 + 版本 ——
  const st=tab('tab-stats'); if(st){ st.replaceChildren();
    element('p','这一页说明"结论从哪来"：整体研判摘要、各环节数量、以及本次分析用到的规则/模型版本，便于复核与留档。',st,'panel-intro');
    element('h3','风险报告摘要',st);
    element('p',(b.report.summary||'未提供'),st,'report-summary');
    const m=b.metrics||{};
    element('h3','处理统计',st);
    const stats=element('div',undefined,st,'fact-grid');
    [['原始事件',m.raw_count],['降噪后',m.denoised_count],['可疑事件',m.suspicious_count],['攻击链',(b.chains||currentTask.chains||[]).length],['攻击活动',(b.campaigns||[]).length],['告警',(b.alerts||currentTask.alerts||[]).length],['攻击者',(b.profiles||[]).length],['M1+M2 全流程耗时',fmtDuration(m.duration_seconds)]].forEach(([k,v])=>{const c=element('div',undefined,stats);element('small',k,c);element('strong',v??'—',c);});
    // 数据质量面板：接入→降噪漏斗 + 坏行隔离明细（来自 M1 status.quality，经 bundle.metrics.quality 透出）
    const q=m.quality||{};const flt=q.filtered||{};
    const pct=v=>(v==null?'—':(Number(v)*100).toFixed(1)+'%');
    element('h3','数据质量',st);
    element('p','以下统计说明这批输入数据的"成色"：多少行被跳过、为什么跳过。解析失败的行会被隔离并跳过，不影响其余数据分析。',st,'panel-intro');
    const qgrid=element('div',undefined,st,'fact-grid');
    [['解析失败行',flt.parse_error??0],['空行跳过',flt.empty??0],['无意义行跳过',flt.meaningless??0],['重复剔除',flt.duplicate??0],['白名单过滤',flt.whitelist??0],['时间戳无法解析',q.timestamp_parse_errors??0]]
      .forEach(([k,v])=>{const c=element('div',undefined,qgrid);element('small',k,c);element('strong',String(v),c);});
    const qgrid2=element('div',undefined,st,'fact-grid');
    [['复核分组数',q.review_groups??'—'],['可疑会话占比',pct(q.suspicious_ratio)],['复核压缩比',pct(q.review_reduction_ratio)],['语义研判覆盖',pct(q.l3_session_coverage)]]
      .forEach(([k,v])=>{const c=element('div',undefined,qgrid2);element('small',k,c);element('strong',String(v),c);});
    const errTotal=(q.parse_errors&&q.parse_errors.total)||0;
    const errSamples=(q.parse_errors&&q.parse_errors.samples)||[];
    if(errTotal>0&&errSamples.length){
      element('p','以下输入行无法解析，已跳过并计入"解析失败行"：',st,'panel-intro');
      errSamples.slice(0,10).forEach(e=>{element('p','· '+(e.source_file||'未知文件')+' 第 '+(e.row??'?')+' 行：'+(e.error||'未知原因'),st,'panel-intro');});
      if(errTotal>errSamples.length) element('p','…其余 '+(errTotal-errSamples.length)+' 条同类错误已按同样方式跳过（明细保留在任务产物中）。',st,'panel-intro');
    }
    if(q.accuracy_status==='requires_human_labels') element('p','检测准确率评估：需要人工标注后离线评估（m1 quality evaluate 工具），当前结论以规则与模型研判为准。',st,'panel-intro');
    element('h3','方法与版本',st);
    const v=b.versions||{};
    const vt=element('table',undefined,st,'data-table compact');
    [['规则版本',v.rule_version],['模型版本',v.model_version],['提示词版本',v.prompt_version],['阈值版本',v.threshold_version],['代码版本',v.code_commit]].forEach(([k,val])=>{const tr=element('tr',undefined,vt);element('td',k,tr);element('td',String(val??'—'),tr);});
    element('p','当前结果'+(b.degraded?'为规则引擎降级产出（LLM 未参与）':'由级联模型与规则引擎联合研判')+ '。数据均来自共享工作区文件，页面统计与本报告同源。',st,'panel-intro');
  }
};
// 结果加载后默认定位到排序后的最高危链（原 loadResults 取服务端首条，顺序不稳定）。
const baseLoadResults=loadResults;
loadResults=async function() {
  await baseLoadResults();
  const sorted=sortChains(currentTask?.chains||[]);
  if(sorted.length){currentChain=sorted[0];chainSelector.value=currentChain.chain_id;renderChain();}
};
// 导出告警：按当前筛选导出 CSV（原为整任务报告 JSON）。
document.querySelector('#export-alerts').onclick=function() {
  const rows=window.__matchingAlerts||[];
  if(!rows.length){flowStatus('当前筛选下没有可导出的告警');return;}
  const esc=v=>'"'+String(v??'').replace(/"/g,'""')+'"';
  const csv='\ufeff'+['alert_id,title,severity,attacker,target,technique,attack_type,confidence,timestamp,task']
    .concat(rows.map(a=>[a.alert_id,a.title,a.severity,a.source,a.target,a.technique,a.attack_type,a.confidence,a.timestamp,a.taskLabel].map(esc).join(',')))
    .join('\n');
  const url=URL.createObjectURL(new Blob([csv],{type:'text/csv'}));
  const link=document.createElement('a');link.href=url;link.download='alerts-'+(currentTask?.task_id||'all')+'.csv';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  flowStatus('已导出 '+rows.length+' 条告警 CSV');
};
// 导出攻击链：导出当前链 JSON（原为整任务报告 JSON）。
document.querySelector('#export-chain').onclick=function() {
  if(!currentChain){flowStatus('没有可导出的攻击链');return;}
  const url=URL.createObjectURL(new Blob([JSON.stringify(currentChain,null,2)],{type:'application/json'}));
  const link=document.createElement('a');link.href=url;link.download=currentChain.chain_id+'.json';link.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
  flowStatus('已导出攻击链 '+currentChain.chain_id);
};
async function loadChatHistory(id,version) {
  try {const rows=await api('/tasks/'+id+'/chat-history');if(version!==selectionVersion)return;
    const panel=document.querySelector('#chat-messages');rows.forEach(r=>{element('p','你：'+r.question,panel);element('p',displayAnswer(r.answer),panel,'assistant-msg');});
  }catch(e){flowStatus('对话历史读取失败：'+e.message);}
}
const shortcuts=element('div',undefined,undefined,'chat-shortcuts');
document.querySelector('#chat-messages').before(shortcuts);
['任务总结','告警多少','主要攻击类型','攻击者 IP','解释当前攻击链的证据','高危原因','哪些攻击链共享攻击者','漏洞修复建议','生成安全日报'].forEach(text=>{
  element('button',text,shortcuts).onclick=()=>{document.querySelector('#chat-input').value=text;document.querySelector('#send-chat').click();};
});
// Refresh all tasks, including tasks not selected in the browser.
setInterval(async()=>{
  if(document.hidden)return;
  try {const before=currentTask?.status;await refreshTasks();renderAlerts();
    if(currentTask?.status==='completed'&&before!=='completed')await loadResults();
    document.querySelector('.system-status span').textContent='服务连接正常';
  }catch(e){document.querySelector('.system-status span').textContent='服务连接中断';}
},15000);

// ── 分析结果整页视图（#report）：整体结论 + 关键指标 + 等级/类型分布 + 建议 + 明细入口 ──
function renderReport() {
  const host = document.getElementById('report-body'); if (!host) return;
  host.replaceChildren();
  const t = currentTask;
  if (!t) { element('div', '尚未选择任务。请到「分析任务」打开一个任务。', host, 'report-empty'); return; }
  const b = t.bundle || {}; const m = b.metrics || {};
  if (t.status !== 'completed' || !b.report) { element('div', '该任务尚无分析结果（状态：' + (t.status || '未知') + '）。', host, 'report-empty'); return; }
  const stat = b.report.statistics || {};
  const sevCounts = m.severity_counts || { critical: stat.critical_count || 0, high: stat.high_count || 0, medium: stat.medium_count || 0, low: stat.low_count || 0, info: stat.info_count || 0 };
  const chainCount = (b.chains || t.chains || []).length || stat.chain_count || 0;
  const eventCount = m.confirmed_events || stat.confirmed_events || (b.alerts || t.alerts || []).length || 0;
  const multistage = m.multistage_chains || stat.multistage_chains || 0;
  const attackers = (b.profiles || []).length;
  const highTop = (sevCounts.critical || 0) + (sevCounts.high || 0);

  const head = element('section', undefined, host, 'panel report-card');
  const meta = element('div', undefined, head, 'report-meta');
  element('span', '任务文件：' + (t.filename || t.task_id), meta);
  element('span', (b.degraded || m.degraded) ? '研判模式：仅规则判定（本批未调用大模型）' : '研判模式：' + analysisModeCN(t.analysis_mode), meta);
  element('h3', '风险报告', head);
  element('p', String(b.report.summary || '（无摘要）'), head, 'report-narrative');

  const decision=element('div',undefined,host,'report-decision');
  element('b','处置判断',decision);
  element('span',multistage?`优先调查 ${multistage} 条多阶段攻击链，再按综合风险分处置其余链。`:`本批以单阶段行为为主，建议按风险分与受影响资产排序处置。`,decision);

  element('h3', '关键指标', host);
  const grid = element('div', undefined, host, 'fact-grid');
  [['接入原始', m.raw_count], ['可疑事件', m.suspicious_count], ['确认攻击事件', eventCount],
   ['攻击链', chainCount], ['多阶段链', multistage], ['高危及以上告警', highTop], ['攻击者画像', attackers], ['M1+M2 全流程耗时', fmtDuration(m.duration_seconds)]]
    .forEach(pair => { const c = element('div', undefined, grid); element('small', pair[0], c); element('strong', (pair[1] == null ? '—' : pair[1]), c); });

  // 降噪漏斗（数据质量）：管道式摘要 + 过滤明细；旧结果包无 quality 时整段跳过
  const q = m.quality || {};
  const flt = q.filtered || {};
  if (m.raw_count != null && ['empty', 'meaningless', 'duplicate', 'whitelist', 'parse_error'].some(k => flt[k] != null)) {
    element('h3', '降噪漏斗', host);
    const strip = element('div', undefined, host, 'funnel-strip');
    const mkStage = (label, value, cls) => { const s = element('div', undefined, strip, 'funnel-stage ' + (cls || ''));
      element('b', String(value == null ? '—' : value), s); element('small', label, s); return s; };
    const mkArrow = () => element('span', '→', strip, 'funnel-arrow');
    const filterNames = { empty: '空行', meaningless: '无意义行', duplicate: '重复', whitelist: '白名单', parse_error: '坏行' };
    const filterItems = Object.entries(filterNames).map(([k, name]) => [name, Number(flt[k]) || 0]);
    const filteredSum = filterItems.reduce((sum, f) => sum + f[1], 0);
    mkStage('原始接入', m.raw_count);
    mkArrow();
    if (filteredSum > 0) {
      filterItems.filter(f => f[1] > 0).forEach(f => { mkStage(f[0] + '过滤', f[1], 'is-filter'); mkArrow(); });
    }
    mkStage('入库会话', (Number(m.raw_count) || 0) - filteredSum);
    mkArrow();
    mkStage('可疑事件', m.suspicious_count);
    mkArrow();
    mkStage('确认告警', eventCount, 'is-alert');
    if (filteredSum > 0) {
      const detail = element('div', undefined, host, 'funnel-filters');
      filterItems.forEach(f => { const chip = element('span', f[0] + ' ' + f[1], detail); if (f[1] > 0) chip.className += ' hit'; });
    } else {
      element('small', '本批五级过滤均未命中（空行/无意义/重复/白名单/坏行），原始行全部入库。', host, 'report-info-note');
    }
    const errs = q.parse_errors || {}; const samples = errs.samples || [];
    if (samples.length) {
      element('small', '坏行样本：' + samples.slice(0, 5).map(s => '第 ' + s.row + ' 行 ' + (s.error || '')).join('；')
        + (errs.total > samples.length ? '（共 ' + errs.total + ' 条）' : ''), host, 'report-info-note');
    }
  }

  const SEV = [['严重', 'critical', '#9f1239'], ['高危', 'high', '#b4232f'], ['中危', 'medium', '#d97a1f'], ['低危', 'low', '#0e7c8c'], ['提示', 'info', '#8a94a6']];
  const totalSev = SEV.reduce((sum, r) => sum + (sevCounts[r[1]] || 0), 0) || 1;
  element('h3', '风险等级分布', host);
  const bars = element('div', undefined, host, 'report-sev');
  SEV.forEach(r => { const cnt = sevCounts[r[1]] || 0; const row = element('div', undefined, bars, 'rs-row');
    element('span', r[0], row, 'rs-label'); const track = element('div', undefined, row, 'rs-track');
    const fill = element('i', undefined, track); fill.style.width = (cnt / totalSev * 100) + '%'; fill.style.background = r[2];
    element('b', cnt + ' 条', row, 'rs-num'); });
  const infoObservations = Number(m.informational_sessions || m.session_risk_counts?.info || 0);
  element('small', `信息级观察会话：${infoObservations} 个（全量会话风险分 <20；观察项，不计入告警）`, host, 'report-info-note');

  const types = Object.entries(m.attack_types || stat.attack_type_counts || {});
  if (types.length) { element('h3', '主要威胁类型', host); const tw = element('div', undefined, host, 'report-types');
    types.sort((a, c) => c[1] - a[1]).slice(0, 8).forEach(kv => { const chip = element('div', undefined, tw, 'type-chip'); element('b', kv[0], chip); element('span', kv[1] + ' 条', chip); }); }

  // 高风险资产双榜单：旗标由 assemble 一次算好（critical/high 硬指针强制在受高威胁榜）
  const victimsAll = b.victims || [];
  const rankedVictims = victimsAll.filter(v => v.threat_score != null);
  if (rankedVictims.length) {
    element('h3', '高风险资产', host);
    const threatRows = victimsAll.filter(v => v.in_threat_ranking).slice(0, 8);
    const freqRows = victimsAll.filter(v => v.in_freq_ranking).slice(0, 8);
    if (threatRows.length) {
      element('small', '受高威胁攻击（最严等级 critical/high 强制在榜；其余按威胁指数相对线补足）', host, 'report-info-note');
      const tw = element('div', undefined, host, 'report-types');
      threatRows.forEach(v => { const chip = element('div', undefined, tw, 'type-chip'); element('b', v.victim_ip || '未知资产', chip);
        element('span', '威胁指数 ' + v.threat_score + ' · ' + sevCN(v.max_severity) + ' · ' + (v.alert_count || 0) + ' 条', chip); });
    }
    if (freqRows.length) {
      element('small', '被多次攻击（按命中告警数的对数指数，榜一恒为 100）', host, 'report-info-note');
      const fw = element('div', undefined, host, 'report-types');
      freqRows.forEach(v => { const chip = element('div', undefined, fw, 'type-chip'); element('b', v.victim_ip || '未知资产', chip);
        element('span', '频次指数 ' + v.freq_score + ' · ' + (v.alert_count || 0) + ' 条', chip); });
    }
  } else {
    const victims = victimsAll.slice(0, 8);
    if (victims.length) { element('h3', '高风险资产', host); const vw = element('div', undefined, host, 'report-types');
      victims.forEach(v => { const chip = element('div', undefined, vw, 'type-chip'); element('b', v.victim_ip || '未知资产', chip);
        element('span', (v.attack_count || 0) + ' 次 · ' + sevCN(v.max_severity) + (v.first_seen ? ' · ' + fmtTime(v.first_seen) : ''), chip); }); }
  }

  const actions = sortActions(b.report.recommended_actions || []).slice(0, 5);
  if (actions.length) { element('h3', '优先处置建议', host); const ab = element('div', undefined, host, 'report-actions-list');
    actions.forEach(a => { const adv = adviceCn(a); const trace=actionTrace(a); const r = element('div', undefined, ab, 'action-row');
      element('span', priorityCN(a.priority), r, 'alert-sev ' + (a.priority || 'info')); const body = element('div', undefined, r, 'action-body');
      element('b', adv.title, body); element('p', adv.text || '', body);
      element('small','依据：'+(a.related_techniques?.length?attCodes(a.related_techniques,ATT_TECH):'安全知识库')+' · 关联 '+trace.related.length+' 条攻击链 / '+trace.evidence.length+' 条证据 · 来源 '+srcCn(a.source),body);
      if(trace.top){const open=element('button','打开最高优先关联链',body,'trace-btn');open.onclick=async()=>{
        currentChain=trace.top;
        if(!Array.isArray(currentChain.stages)) currentChain=await api('/attack-chains/'+encodeURIComponent(currentChain.chain_id));
        populateChainSelector();renderChain();switchView('chains');
      };}
    }); }

  element('h3', '查看明细', host);
  const links = element('div', undefined, host, 'report-links');
  [['逐条攻击链还原', 'chains'], ['全部告警明细', 'alerts'], ['管理分析任务', 'tasks']].forEach(pair => {
    const btn = element('button', undefined, links, 'secondary-btn'); element('span', pair[0] + ' →', btn); btn.onclick = () => switchView(pair[1]); });
}
