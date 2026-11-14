"""M1 本地 IOC 库(SQLite, 真实数据) -> M2 威胁情报 parquet（矛盾点 #6）。

M1 的 local_ioc 库来自 Spamhaus DROP(IPv4/IPv6) + OpenPhish Community(URL)，是真实情报；
M2 自带的是脚本生成的占位假数据。本脚本把真实库导出为 M2 LocalThreatIntelProvider
可读的 parquet（indicator/malicious/confidence/source/tags/description），
保持 M2 不 import M1 代码的原则。CIDR 网段 M2 是精确匹配索引，暂不导出（记录跳过数）。
"""

from __future__ import annotations

import argparse
import json
import ipaddress
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pyarrow as pa
import pyarrow.parquet as pq

COLUMNS = ["indicator", "malicious", "confidence", "source", "tags", "description", "last_seen"]


def _table(rows: list[dict]) -> pa.Table:
    return pa.table({name: pa.array([row.get(name) for row in rows]) for name in COLUMNS})


def export_intel(m1_workspace: Path, intel_dir: Path, expand_cidr: int = 300) -> dict:
    db_path = Path(m1_workspace) / "m1" / "local_ioc" / "ioc.sqlite3"
    if not db_path.is_file():
        raise FileNotFoundError(f"M1 IOC 库不存在: {db_path}（先运行 scripts/update_ioc.bat）")

    now_iso = datetime.now(timezone.utc).isoformat()
    ip_rows: list[dict] = []
    domain_rows: list[dict] = []
    skipped_cidr = 0
    skipped_expired = 0
    expanded_hosts = 0

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    try:
        cursor = conn.execute(
            "SELECT kind, value, source, fetched_at, expires_at FROM indicators")
        for kind, value, source, fetched_at, expires_at in cursor:
            if not value:
                continue
            if expires_at:
                try:
                    if datetime.fromisoformat(expires_at) < datetime.now(timezone.utc):
                        skipped_expired += 1
                        continue
                except ValueError:
                    pass
            kind_l = (kind or "").lower()
            row = {
                "indicator": value,
                "malicious": True,
                "confidence": 0.9,
                "source": source or "m1_local_ioc",
                "tags": "spamhaus_drop" if "spamhaus" in (source or "").lower() else (
                    "openphish" if "openphish" in (source or "").lower() else "m1_ioc"),
                "description": f"M1 本地IOC库 ({source}); fetched {fetched_at}",
                "last_seen": fetched_at or now_iso,
            }
            if kind_l in ("cidr", "netblock"):
                # DROP 语义=网段内地址全部拒绝。M2 为精确匹配索引，展开部分宿主地址
                # （有限样本）使网段级情报可被 M2 富化命中；全量匹配仍由 M1 网段索引负责。
                if expand_cidr > 0 and expanded_hosts < expand_cidr and ":" not in value:
                    try:
                        network = ipaddress.ip_network(value, strict=False)
                        for host in list(network.hosts())[: max(1, expand_cidr - expanded_hosts)]:
                            ip_rows.append({**row, "indicator": str(host),
                                            "description": f"Spamhaus DROP 网段 {value} 展开样本 ({source})"})
                            expanded_hosts += 1
                    except ValueError:
                        pass
                skipped_cidr += 1
                continue
            if kind_l in ("ipv4", "ipv6", "ip"):
                ip_rows.append(row)
            elif kind_l in ("url",):
                host = urlsplit(value).netloc.split("@")[-1].split(":")[0]
                if host:
                    domain_rows.append({**row, "indicator": host})
            elif kind_l in ("domain", "hostname"):
                domain_rows.append(row)
    finally:
        conn.close()

    # 去重（OpenPhish 多条 URL 可能同 host）
    def dedupe(rows: list[dict]) -> list[dict]:
        seen: set[str] = set()
        unique = []
        for row in rows:
            key = row["indicator"]
            if key in seen:
                continue
            seen.add(key)
            unique.append(row)
        return unique

    ip_rows, domain_rows = dedupe(ip_rows), dedupe(domain_rows)

    intel_dir = Path(intel_dir)
    intel_dir.mkdir(parents=True, exist_ok=True)
    (intel_dir / "ip_reputation.parquet").unlink(missing_ok=True)
    (intel_dir / "domains.parquet").unlink(missing_ok=True)
    if ip_rows:
        pq.write_table(_table(ip_rows), intel_dir / "ip_reputation.parquet")
    if domain_rows:
        pq.write_table(_table(domain_rows), intel_dir / "domains.parquet")

    return {
        "db": str(db_path),
        "ip_indicators": len(ip_rows),
        "domain_indicators": len(domain_rows),
        "skipped_cidr": skipped_cidr,
        "expanded_hosts": expanded_hosts,
        "skipped_expired": skipped_expired,
        "intel_dir": str(intel_dir),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Bridge: M1 IOC sqlite -> M2 threat intel parquet")
    parser.add_argument("--m1-workspace", required=True, help="M1 工作区根（含 m1/local_ioc/ioc.sqlite3）")
    parser.add_argument("--intel-dir", required=True, help="M2 threat_intel 目录")
    args = parser.parse_args()
    stats = export_intel(Path(args.m1_workspace), Path(args.intel_dir))
    print(json.dumps(stats, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
