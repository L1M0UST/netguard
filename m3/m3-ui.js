// M3 renders producer-supplied facts and relationships only.
const SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' };
const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
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
    details(evidence,'关联证据（原始请求，已脱敏）',(currentTask.bundle?.evidence||[]).filter(e=>(stage.evidence_event_ids||[]).includes(e.event_id)).slice(0,20));
  }
  (currentChain.edges||[]).forEach(([from,to],i)=>{
    const a=positions.get(from),b=positions.get(to); if(!a||!b)return;
    const x=boxW+60+(i%8)*20;
    shape('path',{d:`M ${boxW+40} ${a.y+42} H ${x} V ${b.y+42} H ${boxW+48}`,fill:'none',stroke:'#6375cf','stroke-width':2});
    shape('path',{d:`M ${boxW+50} ${b.y+37} L ${boxW+40} ${b.y+42} L ${boxW+50} ${b.y+47}`,fill:'none',stroke:'#6375cf','stroke-width':2});
  });
  stages.forEach((stage,idx)=>{
    const p=positions.get(stage.stage_id);
    const t=attCn(stage.tactic), te=attCn(stage.technique);
    const g=shape('g',{tabindex:0,role:'button','aria-label':('阶段'+(idx+1)+' '+t.cn+' '+te.cn+' 查看证据')});
    const rect=document.createElementNS(svg.namespaceURI,'rect');
    rect.setAttribute('x',p.x);rect.setAttribute('y',p.y);rect.setAttribute('width',boxW);rect.setAttribute('height',86);
    rect.setAttribute('rx',12);rect.setAttribute('fill','#eef4ff');rect.setAttribute('stroke','#b7c9f2');rect.setAttribute('class','chain-stage-box');
    g.append(rect);
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

renderBundle=function() {
  const sorted=sortChains(currentTask.chains||[]);
  populateChainSelector();
  const b=currentTask.bundle; if(!b) return;
  const tab=id=>document.getElementById(id);

  // —— ② 攻击者画像：紧凑表格，不再铺 JSON 卡 ——
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

  // —— ③ 处置建议：列表 ——
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

  // —— ④ 证据与统计：报告摘要 + 指标 + 版本 ——
  const st=tab('tab-stats'); if(st){ st.replaceChildren();
    element('p','这一页说明"结论从哪来"：整体研判摘要、各环节数量、以及本次分析用到的规则/模型版本，便于复核与留档。',st,'panel-intro');
    element('h3','风险报告摘要',st);
    element('p',(b.report.summary||'未提供'),st,'report-summary');
    const m=b.metrics||{};
    element('h3','处理统计',st);
    const stats=element('div',undefined,st,'fact-grid');
    [['原始事件',m.raw_count],['降噪后',m.denoised_count],['可疑事件',m.suspicious_count],['攻击链',(b.chains||currentTask.chains||[]).length],['告警',(b.alerts||currentTask.alerts||[]).length],['攻击者',(b.profiles||[]).length],['M1+M2 全流程耗时',fmtDuration(m.duration_seconds)]].forEach(([k,v])=>{const c=element('div',undefined,stats);element('small',k,c);element('strong',v??'—',c);});
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
