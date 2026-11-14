"""下载并压缩公开威胁知识，供 M3 离线查询。

来源：CISA Known Exploited Vulnerabilities、MITRE ATT&CK STIX 2.1。
只保留产品查询需要的字段，避免前端运行时加载 50MB 以上原始 STIX。
"""
from __future__ import annotations

import json
import os
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "threat_intel_public"
SOURCES = {
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "mitre_attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
}


def fetch(url: str) -> dict:
    proxy = os.getenv("NETGUARD_INTEL_PROXY") or os.getenv("HTTPS_PROXY") or ""
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy})] if proxy else []
    request = urllib.request.Request(url, headers={"User-Agent": "NetGuard-public-intel/1.0"})
    with urllib.request.build_opener(*handlers).open(request, timeout=90) as response:
        return json.loads(response.read().decode("utf-8"))


def build_kev(payload: dict) -> dict:
    rows = {}
    for item in payload.get("vulnerabilities", []):
        cve = str(item.get("cveID") or "").upper()
        if cve:
            rows[cve] = {k: item.get(k) for k in (
                "vendorProject", "product", "vulnerabilityName", "dateAdded",
                "shortDescription", "requiredAction", "dueDate", "knownRansomwareCampaignUse", "notes"
            )}
    return {"source": "CISA KEV", "catalog_version": payload.get("catalogVersion"),
            "updated_at": datetime.now(timezone.utc).isoformat(), "items": rows}


def build_attack(payload: dict) -> dict:
    objects = payload.get("objects", [])
    courses = {obj.get("id"): obj for obj in objects if obj.get("type") == "course-of-action"}
    mitigations: dict[str, list[str]] = {}
    for obj in objects:
        if obj.get("type") == "relationship" and obj.get("relationship_type") == "mitigates":
            name = (courses.get(obj.get("source_ref")) or {}).get("name")
            if name:
                mitigations.setdefault(obj.get("target_ref"), []).append(name)
    rows = {}
    for obj in objects:
        if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        external = next((r for r in obj.get("external_references", [])
                         if r.get("source_name") == "mitre-attack" and r.get("external_id")), None)
        if not external:
            continue
        rows[external["external_id"]] = {
            "name": obj.get("name"),
            "description": str(obj.get("description") or "")[:1800],
            "url": external.get("url"),
            "platforms": obj.get("x_mitre_platforms", []),
            "tactics": [p.get("phase_name") for p in obj.get("kill_chain_phases", []) if p.get("phase_name")],
            "mitigations": sorted(set(mitigations.get(obj.get("id"), [])))[:12],
            "modified": obj.get("modified"),
        }
    return {"source": "MITRE ATT&CK Enterprise STIX 2.1", "spec_version": payload.get("spec_version"),
            "updated_at": datetime.now(timezone.utc).isoformat(), "items": rows}


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    kev = build_kev(fetch(SOURCES["cisa_kev"]))
    attack = build_attack(fetch(SOURCES["mitre_attack"]))
    (OUT / "cisa_kev.json").write_text(json.dumps(kev, ensure_ascii=False, indent=2), encoding="utf-8")
    (OUT / "mitre_attack_enterprise.json").write_text(json.dumps(attack, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = {"updated_at": datetime.now(timezone.utc).isoformat(), "sources": SOURCES,
                "counts": {"cisa_kev": len(kev["items"]), "mitre_attack": len(attack["items"])}}
    (OUT / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(manifest, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
