"""Download the pinned public source files used in the CQSec 8B plan.

This fetches source material only. It does not label, split, or create SFT data.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
import time
import urllib.request
from pathlib import Path


MANIFEST = Path(__file__).with_name("sources.json")


def digest(path: Path, algorithm: str) -> str:
    h = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(item: dict, root: Path) -> None:
    dest = root / item["dataset"] / item["name"]
    dest.parent.mkdir(parents=True, exist_ok=True)
    algorithm, expected = item["checksum"].split(":", 1)
    if dest.exists():
        if dest.is_file() and digest(dest, algorithm) == expected:
            print(f"已验证，跳过: {dest}")
            return
        raise RuntimeError(f"已有文件与校验值不一致，未覆盖: {dest}")
    for attempt in range(1, 4):
        request = urllib.request.Request(item["url"], headers={"User-Agent": "Mozilla/5.0 cqsec-research-data/1.0"})
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(dir=dest.parent, prefix=".cqsec-download-", delete=False) as tmp:
                tmp_path = Path(tmp.name)
                hasher = hashlib.new(algorithm)
                size = 0
                with urllib.request.urlopen(request, timeout=120) as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b""):
                        tmp.write(chunk)
                        hasher.update(chunk)
                        size += len(chunk)
            if hasher.hexdigest() != expected or size != item["size"]:
                raise RuntimeError(f"校验失败: {item['name']} (bytes={size})")
            # Do not overwrite an independently created destination.
            if dest.exists():
                raise RuntimeError(f"下载期间目标文件已出现，未覆盖: {dest}")
            os.replace(tmp_path, dest)
            tmp_path = None
            print(f"下载并验证: {dest} ({size} bytes; {item['role']})", flush=True)
            return
        except (OSError, RuntimeError) as exc:
            if attempt == 3:
                raise
            print(f"{item['name']} 第 {attempt} 次失败，将重试: {type(exc).__name__}", flush=True)
            time.sleep(attempt)
        finally:
            if tmp_path is not None and tmp_path.exists():
                tmp_path.unlink()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", choices=["d1", "d2", "d3"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--list", action="store_true", help="只显示文件，不下载")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    selected = [item for item in manifest["files"] if item["dataset"] == args.dataset]
    total = sum(item["size"] for item in selected)
    print(f"{args.dataset}: {len(selected)} files, {total} bytes")
    if args.list:
        for item in selected:
            print(item["name"], item["size"], item["role"])
        return
    for item in selected:
        fetch(item, args.output)


if __name__ == "__main__":
    main()
