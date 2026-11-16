"""Package the CQSec tool and pilot train/dev, excluding raw and sealed test."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path


KIT_FILES = (
    "操作手册.md", "requirements-constraints.txt", "sources.json", "fetch_data.py",
    "prepare_d1_draft.py", "audit_d1_near.py", "exclude_d1_candidates.py", "make_pilot_subset.py",
    "check_sft_data.py", "make_smoke_data.py", "eval_d1.py", "profile_tokens.py", "estimate_runtime.py",
    "test_toolkit.py", "build_cloud_package.py",
    "configs/smoke.yaml", "configs/profile_a.yaml", "configs/round_a.yaml",
    "configs/round_b.yaml", "configs/round_c.yaml", "configs/export.yaml",
)
DATA_FILES = ("train.jsonl", "dev.jsonl", "dataset_info.json", "subset_report.json")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--token-profile", type=Path)
    parser.add_argument("--audit-report", type=Path)
    parser.add_argument("--filter-report", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit(f"输出文件已存在，未覆盖: {args.output}")
    kit = Path(__file__).resolve().parent
    items = [(kit / name, "cqsec8b/" + name) for name in KIT_FILES]
    items += [(args.data_dir / name, "cqsec8b/data/round_a/" + name) for name in DATA_FILES]
    if args.token_profile:
        items.append((args.token_profile, "cqsec8b/reports/local_token_profile.json"))
    if args.audit_report:
        items.append((args.audit_report, "cqsec8b/reports/local_near_audit.json"))
    if args.filter_report:
        items.append((args.filter_report, "cqsec8b/reports/local_filter_report.json"))
    for path, _ in items:
        if not path.is_file():
            raise FileNotFoundError(path)
    manifest = {"purpose": "D1-only pilot; not final multi-source SFT", "contains_sealed_test": False, "files": {}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(args.output, mode="x", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for source, name in items:
            raw = source.read_bytes()
            manifest["files"][name] = {"size": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
            archive.writestr(name, raw)
        archive.writestr("cqsec8b/package-manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    with zipfile.ZipFile(args.output) as archive:
        bad = archive.testzip()
        if bad:
            raise RuntimeError(f"ZIP CRC failure: {bad}")
        if any(name.endswith("/test.jsonl") for name in archive.namelist()):
            raise RuntimeError("sealed test unexpectedly included")
    digest = hashlib.sha256(args.output.read_bytes()).hexdigest()
    print(json.dumps({"package": str(args.output), "size": args.output.stat().st_size,
                      "sha256": digest, "files": len(items) + 1, "sealed_test_included": False}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
