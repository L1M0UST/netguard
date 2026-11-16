function renderTaskGraph(b, host) {
  const g=b.graph;
  element('p','这张图由 NetworkX 在后端建图：节点=攻击源 / 受害资产 / 攻击链，边=发起 / 命中 / 战役归并；底色相同的节点是社区发现聚出的同一活动簇。节点可拖拽、滚轮缩放、悬浮高亮关联边；点击链节点跳转路径图，点击 IP 展开它涉及的链。',host,'panel-intro');
  if(!g||!g.nodes||!g.nodes.length){ element('p','本任务结果包未包含关联图（重新分析后生成）；下方"攻击活动"页仍有战役归并明细。',host,'empty-state'); return; }
  const st=g.stats||{};
  const statsBar=element('div',undefined,host,'graph-stats');
  [['节点',st.node_count],['边',st.edge_count],['连通簇',st.component_count],['社区',st.community_count]].forEach(([k,v])=>{const c=element('span',undefined,statsBar,'graph-stat');element('small',k,c);element('b',String(v??'—'),c);});
  if(g.note){ element('small',g.note,statsBar,'graph-note').title='大规模任务的截断策略：保证图可读，完整链仍走链选择器'; }
  const legend=element('div',undefined,host,'graph-legend');
  const lgChip=element('span',undefined,legend,'lg-item'); element('i',undefined,lgChip,'lg-sw lg-chain'); element('small','链节点（描边=危险等级，底色=社区）',lgChip);
  const lgA=element('span',undefined,legend,'lg-item'); element('i',undefined,lgA,'lg-sw lg-att'); element('small','攻击源',lgA);
  const lgV=element('span',undefined,legend,'lg-item'); element('i',undefined,lgV,'lg-sw lg-vic'); element('small','受害资产',lgV);
  const lgE=element('span',undefined,legend,'lg-item'); element('i',undefined,lgE,'lg-line'); element('small','发起 / 命中',lgE);
  const lgC=element('span',undefined,legend,'lg-item'); element('i',undefined,lgC,'lg-line lg-camp'); element('small','战役归并',lgC);
  const W=(g.canvas&&g.canvas.width)||900, H=(g.canvas&&g.canvas.height)||600;
  const wrap=element('div',undefined,host,'graph-viewport task-graph');
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
  const info=element('div',undefined,host,'task-graph-info');
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
