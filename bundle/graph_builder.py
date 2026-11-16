"""NetworkX 关联图构建器（AttackGraph.v1）。

第四方面验收口径里"图遍历、社区发现"的真实实现：
- 图模型节点 = 攻击源 IP / 受害资产 IP / 攻击链（对应"IP、资产、告警"）；
- 边 = 发起(attacker→chain)、命中(chain→victim)、战役归并(chain→chain，带理由与间隔)；
- 算法 = 连通分量（活动簇计数）、greedy_modularity_communities（社区发现）、
  degree_centrality（关键节点排序）、spring_layout（确定性种子布局坐标）。
前端拿到坐标后用 SVG 渲染并保留全部交互（拖节点/缩放/悬浮边理由/点击跳链），
NetworkX 本身不进浏览器。

大规模截断：万级任务可产生数千链，整图渲染既慢又不可读——
  链节点 = 多链战役成员（每战役按风险分取前 CHAINS_PER_CAMPAIGN 条）
         + 独立链按风险分取前 TOP_STANDALONE 条；
  IP 节点 = 仅保留与入选链相连的地址；若仍超 MAX_NODES，按度数递减再截。
截断在 stats.note 中如实说明，绝不假装渲染了全量。
"""

from __future__ import annotations

from datetime import datetime

import networkx as nx

PAD = 42          # 画布四周留白
CHAINS_PER_CAMPAIGN = 6
TOP_STANDALONE = 24
MAX_CAMPAIGNS = 16   # 进图的战役数在选链层封顶（风险最高的前 N 个）
MAX_NODES = 260      # 度数兜底防线，正常路径不触发
MAX_COMMUNITIES = 60 # 社区截断防线：独立链各成一簇，正常时不会超过该值


def _ts(value) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (ValueError, TypeError):
        return None


def _risk_of(chain: dict) -> float:
    score = (chain.get("risk_score") or {}).get("score")
    if isinstance(score, (int, float)):
        return float(score)
    return 0.0


def _short_chain_id(chain_id: str) -> str:
    return chain_id[len("chain_"):][:16] if chain_id.startswith("chain_") else chain_id[:16]


def select_chains(chains: list[dict], campaigns: list[dict]) -> tuple[list[dict], int, bool]:
    """挑进入图的链：风险最高的前 MAX_CAMPAIGNS 个战役（每战役按风险截断）+ 高风险独立链。

    战役数在选链层就封顶：先在全部战役里挑最危险的 MAX_CAMPAIGNS 个，
    再对每个战役取前 CHAINS_PER_CAMPAIGN 条成员链——这样社区/布局层不会
    把战役的归并边整批砍掉（万级实测：先选全部战役再砍节点，254 边只剩 25）。
    返回 (入选链, 成员被截断的战役数, 是否发生截断)。
    """
    by_id = {c["chain_id"]: c for c in chains}

    def campaign_risk(campaign: dict) -> float:
        return max((_risk_of(by_id[m["chain_id"]])
                    for m in (campaign.get("members") or []) if m.get("chain_id") in by_id),
                   default=0.0)

    ranked_campaigns = sorted(campaigns, key=lambda c: (-campaign_risk(c), str(c.get("campaign_id"))))
    chosen: dict[str, dict] = {}
    trimmed_campaigns = 0
    for campaign in ranked_campaigns[:MAX_CAMPAIGNS]:
        ranked = sorted(
            (m for m in (campaign.get("members") or []) if m.get("chain_id") in by_id),
            key=lambda m: -_risk_of(by_id[m["chain_id"]]),
        )
        picked = ranked[:CHAINS_PER_CAMPAIGN]
        if len(ranked) > CHAINS_PER_CAMPAIGN:
            trimmed_campaigns += 1
        for member in picked:
            chosen[member["chain_id"]] = by_id[member["chain_id"]]
    standalone = [c for c in chains if not c.get("campaign_id") and c["chain_id"] not in chosen]
    standalone.sort(key=lambda c: (-_risk_of(c), c["chain_id"]))
    for chain in standalone[:TOP_STANDALONE]:
        chosen[chain["chain_id"]] = chain
    truncated = (trimmed_campaigns > 0 or len(standalone) > TOP_STANDALONE
                 or len(ranked_campaigns) > MAX_CAMPAIGNS)
    return list(chosen.values()), trimmed_campaigns, truncated


def build_attack_graph(task_id: str, chains: list[dict], campaigns: list[dict]) -> dict:
    """把链与实体组成网络并回传可渲染的图 JSON（含坐标/社区/中心性）。"""
    chosen, trimmed_campaigns, truncated = select_chains(chains, campaigns)
    graph = nx.DiGraph()

    def chain_node_id(chain_id: str) -> str:
        return f"chain:{chain_id}"

    def ip_node_id(ip: str) -> str:
        return f"ip:{ip}"

    chain_attrs: dict[str, dict] = {}
    for chain in chosen:
        cid = chain["chain_id"]
        nid = chain_node_id(cid)
        attrs = {
            "type": "chain",
            "label": _short_chain_id(cid),
            "chain_id": cid,
            "severity": chain.get("severity") or "info",
            "risk_score": _risk_of(chain),
            "stage_count": len(chain.get("stages") or []),
            "campaign_id": chain.get("campaign_id"),
            "first_seen": chain.get("first_seen"),
            "last_seen": chain.get("last_seen"),
            "roles": [],
        }
        graph.add_node(nid, **attrs)
        chain_attrs[cid] = attrs
        for ip in (chain.get("attacker_ips") or [])[:3]:
            graph.add_edge(ip_node_id(ip), nid, type="launches",
                           reason=f"链 {cid} 由攻击源 {ip} 发起")
        for ip in (chain.get("victim_ips") or [])[:3]:
            graph.add_edge(nid, ip_node_id(ip), type="targets",
                           reason=f"链 {cid} 命中资产 {ip}")

    # IP 节点属性：角色（可能既是攻击源又是受害资产）、度数
    for node_id, data in graph.nodes(data=True):
        if data.get("type"):
            continue
        ip = node_id[3:]
        roles = set()
        if any(graph.has_edge(node_id, succ) for succ in graph.successors(node_id)):
            roles.add("attacker")
        if any(graph.has_edge(pred, node_id) for pred in graph.predecessors(node_id)):
            roles.add("victim")
        data.update({
            "type": "ip",
            "label": ip,
            "roles": sorted(roles) or ["attacker"],
        })

    # 战役归并边：成员按时间排序相邻相连，理由取战役级归并依据
    campaign_by_id = {c["campaign_id"]: c for c in campaigns}
    for chain in chosen:
        cid_key = chain.get("campaign_id")
        if not cid_key:
            continue
        campaign = campaign_by_id.get(cid_key)
        if not campaign:
            continue
        members = [m for m in (campaign.get("members") or []) if m["chain_id"] in chain_attrs]
        members.sort(key=lambda m: _ts(m.get("first_seen")) or 0.0)
        reason = "；".join((campaign.get("reasons") or [])[:2]) or "同一攻击活动"
        for a, b in zip(members, members[1:]):
            gap = None
            t1, t2 = _ts(a.get("last_seen")), _ts(b.get("first_seen"))
            if t1 is not None and t2 is not None:
                gap = round(max(0.0, t2 - t1), 1)
            graph.add_edge(chain_node_id(a["chain_id"]), chain_node_id(b["chain_id"]),
                           type="campaign", reason=reason, gap_seconds=gap,
                           campaign_id=cid_key)

    # 规模兜底：理论截断已限流，防御性再截一次（按度数保关键节点）
    truncated2 = False
    if graph.number_of_nodes() > MAX_NODES:
        truncated2 = True
        keep = sorted(graph.nodes(), key=lambda n: -graph.degree(n))[:MAX_NODES]
        graph = graph.subgraph(keep).copy()

    undirected = graph.to_undirected()
    stats: dict = {
        "node_count": graph.number_of_nodes(),
        "edge_count": graph.number_of_edges(),
        "truncated": bool(truncated or truncated2),
    }
    if trimmed_campaigns:
        stats["trimmed_campaigns"] = trimmed_campaigns

    # 社区发现（greedy modularity）：同一活动簇的节点自动聚类
    communities: list[set[str]] = []
    if undirected.number_of_nodes() >= 3 and undirected.number_of_edges() >= 2:
        try:
            communities = [set(c) for c in nx.community.greedy_modularity_communities(undirected)]
        except Exception:  # noqa: BLE001 - 社区发现失败不阻塞出图
            communities = []
    for index, members in enumerate(communities):
        for node_id in members:
            graph.nodes[node_id]["community"] = index

    # 社区截断（第二层）：万级任务可聚出上百个小簇，全部画会稀释重点——
    # 只保留"成员链风险分最高"的前 MAX_COMMUNITIES 个簇，其余节点从图中移除并如实说明。
    if len(communities) > MAX_COMMUNITIES:
        def _cluster_risk(members: set[str]) -> float:
            return max((graph.nodes[n].get("risk_score") or 0.0
                        for n in members if graph.nodes[n].get("type") == "chain"),
                       default=0.0)
        communities.sort(key=lambda m: (-_cluster_risk(m), min(m)))
        dropped = communities[MAX_COMMUNITIES:]
        communities = communities[:MAX_COMMUNITIES]
        drop_ids = set().union(*dropped) if dropped else set()
        if drop_ids:
            graph.remove_nodes_from(drop_ids)
            undirected = graph.to_undirected()
            stats["truncated"] = True
            stats["dropped_communities"] = len(dropped)
    for index, members in enumerate(communities):
        for node_id in members:
            graph.nodes[node_id]["community"] = index
    stats["community_count"] = len(communities)

    # 连通分量 = 图上的"活动簇"数量（含独立链的孤立点）
    stats["component_count"] = nx.number_connected_components(undirected)

    # 确定性社区网格布局（替代 spring_layout）：
    # spring 的单位间距 ~1/sqrt(n)，在 150+ 节点时约 38px，远小于芯片尺寸(112-126px)，
    # 260 个芯片物理装不进 960px 画布——节点全部叠成一团（万级实测的教训）。
    # 网格布局把社区发现的结果直接画出来：簇内节点排网格，簇间按货架打包，
    # 大簇（风险最高）放左上，小簇靠右下；坐标确定、无随机性。
    clusters: list[list[str]] = []
    placed: set[str] = set()
    for members in communities:
        ordered_members = sorted(members, key=lambda n: (
            0 if graph.nodes[n].get("type") == "ip" else 1,   # IP 在左、链在右
            -graph.degree(n), str(n)))
        clusters.append(ordered_members)
        placed.update(members)
    leftovers = [n for n in graph.nodes() if n not in placed]
    if leftovers:
        clusters.append(sorted(leftovers, key=lambda n: (graph.nodes[n].get("type") or "", str(n))))
    CELL_W, CELL_H, OUTER_GAP = 150, 62, 26
    MAX_ROW_W = 1240
    blocks = []
    for members in clusters:
        cols = max(1, min(4, int(len(members) ** 0.5 + 0.999)))
        rows = (len(members) + cols - 1) // cols
        blocks.append({
            "members": members, "cols": cols, "rows": rows,
            "w": cols * CELL_W, "h": rows * CELL_H,
            "risk": max((graph.nodes[n].get("risk_score") or 0.0
                         for n in members if graph.nodes[n].get("type") == "chain"),
                        default=0.0),
        })
    blocks.sort(key=lambda b: (-b["risk"], -len(b["members"]), b["members"][0]))
    x_cursor, y_cursor, row_h = 0.0, 0.0, 0.0
    content_w, content_h = 0.0, 0.0
    for block in blocks:
        if x_cursor > 0 and x_cursor + block["w"] + OUTER_GAP > MAX_ROW_W:
            x_cursor = 0.0
            y_cursor += row_h + OUTER_GAP
            row_h = 0.0
        for i, node_id in enumerate(block["members"]):
            r, c = divmod(i, block["cols"])
            data = graph.nodes[node_id]
            data["x"] = round(x_cursor + c * CELL_W + CELL_W / 2, 1)
            data["y"] = round(y_cursor + r * CELL_H + CELL_H / 2, 1)
        content_w = max(content_w, x_cursor + block["w"])
        content_h = max(content_h, y_cursor + block["h"])
        x_cursor += block["w"] + OUTER_GAP
        row_h = max(row_h, block["h"])
    canvas_w = int(max(540, min(1240, content_w + 2 * PAD)))
    canvas_h = int(max(320, round(content_h + 2 * PAD)))  # 高度不封顶：外层容器滚动
    shift_x = (canvas_w - content_w) / 2
    for node_id, data in graph.nodes(data=True):
        data["x"] = round(data["x"] + shift_x, 1)
    CANVAS_W = canvas_w
    CANVAS_H = canvas_h

    # 关键 IP（度中心性）：威胁指标排序的图形依据
    centrality = nx.degree_centrality(graph)
    ip_scores = [(node_id, score) for node_id, score in centrality.items()
                 if graph.nodes[node_id].get("type") == "ip"]
    ip_scores.sort(key=lambda item: (-item[1], item[0]))
    stats["top_ips"] = [{
        "ip": graph.nodes[node_id]["label"],
        "roles": graph.nodes[node_id]["roles"],
        "degree": graph.degree(node_id),
        "centrality": round(score, 3),
    } for node_id, score in ip_scores[:6]]

    nodes_out = []
    for node_id, data in graph.nodes(data=True):
        nodes_out.append({
            "id": node_id,
            "type": data.get("type"),
            "label": data.get("label"),
            "roles": data.get("roles") or [],
            "degree": graph.degree(node_id),
            "community": data.get("community"),
            "x": data["x"], "y": data["y"],
            **({k: data[k] for k in ("chain_id", "severity", "risk_score", "stage_count",
                                     "campaign_id", "first_seen", "last_seen") if data.get(k) is not None}),
        })
    edges_out = [{
        "source": u, "target": v,
        "type": data.get("type"),
        "reason": data.get("reason") or "",
        **({"gap_seconds": data["gap_seconds"]} if data.get("gap_seconds") is not None else {}),
        **({"campaign_id": data["campaign_id"]} if data.get("campaign_id") else {}),
    } for u, v, data in graph.edges(data=True)]
    edges_out.sort(key=lambda e: (e["type"], e["source"], e["target"]))
    nodes_out.sort(key=lambda n: (n["type"] or "", n["id"]))

    note_parts = []
    if stats["truncated"]:
        note_parts.append(
            f"图为可读性截断：每战役最多 {CHAINS_PER_CAMPAIGN} 条代表链 + 独立链前 {TOP_STANDALONE} 条"
            + (f"，{trimmed_campaigns} 个战役未展开全部成员" if trimmed_campaigns else "")
            + (f"，仅展示风险最高的 {MAX_COMMUNITIES} 个社区簇（其余 {stats.get('dropped_communities', 0)} 个簇省略）"
               if stats.get("dropped_communities") else ""))
    return {
        "schema_version": "AttackGraph.v1",
        "task_id": task_id,
        "algorithm": f"networkx-{nx.__version__} (greedy_modularity + degree_centrality + community-grid layout)",
        "canvas": {"width": CANVAS_W, "height": CANVAS_H},
        "nodes": nodes_out,
        "edges": edges_out,
        "stats": stats,
        "note": "；".join(note_parts) or None,
    }
