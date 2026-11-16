"""Check split isolation and make a train/dev-only upload for the GPU instance."""
from __future__ import annotations

import collections
import hashlib
import json
import random
import re
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

ROOT = Path(r"E:\platform_taishi\mist8b-web-data\20261115_v3")
DEST = ROOT.parent / "mist8b-web-train-dev-v4.zip"
LABEL_RE = re.compile(r"攻击类型[:：]\s*([^\n；;，,。]+)")


def load(name: str) -> list[dict]:
    result = []
    with (ROOT / (name + ".jsonl")).open(encoding="utf-8") as stream:
        for line in stream:
            row = json.loads(line)
            m = row["_meta"]
            assert m["split"] == name
            match = LABEL_RE.search(row["output"])
            assert match and match.group(1).strip() == m["label"]
            assert all(row.get(k) for k in ("instruction", "input", "output"))
            result.append(row)
    return result


def main() -> None:
    splits = {name: load(name) for name in ("train", "dev", "test")}
    for name, rows in splits.items():
        ids = [r["_meta"]["record_id"] for r in rows]
        assert len(ids) == len(set(ids)), f"duplicate ID in {name}"
    for a, b in (("train", "dev"), ("train", "test"), ("dev", "test")):
        for field in ("record_id", "group_id"):
            left = {r["_meta"][field] for r in splits[a]}
            right = {r["_meta"][field] for r in splits[b]}
            assert left.isdisjoint(right), f"{field} overlaps {a}/{b}"

    groups: dict[tuple[str, str], list[dict]] = collections.defaultdict(list)
    for row in splits["dev"]:
        m = row["_meta"]
        groups[(m["source"], m["label"])].append(row)
    rng = random.Random(42)
    dev = []
    for key in sorted(groups):
        choices = sorted(groups[key], key=lambda row: row["_meta"]["record_id"])
        dev.extend(rng.sample(choices, min(20, len(choices))))
    rng.shuffle(dev)

    def as_jsonl(rows: list[dict]) -> bytes:
        # The actual M1 client places instruction, two newlines, and the seven
        # fields in ONE user message. Supply exactly that to LlamaFactory instead
        # of relying on its Alpaca instruction/query join policy.
        prepared = [dict(row, training_prompt=row["instruction"] + "\n\n" + row["input"], blank_query="")
                    for row in rows]
        return ("\n".join(json.dumps(row, ensure_ascii=False) for row in prepared) + "\n").encode("utf-8")

    dataset = json.loads((ROOT / "dataset_info.json").read_text(encoding="utf-8"))
    for entry in dataset.values():
        entry["columns"]["prompt"] = "training_prompt"
        entry["columns"]["query"] = "blank_query"
    with ZipFile(DEST, "x", compression=ZIP_DEFLATED, compresslevel=6) as archive:
        archive.writestr("data/web_v4/train.jsonl", as_jsonl(splits["train"]))
        archive.writestr("data/web_v4/dev.jsonl", as_jsonl(dev))
        archive.writestr("data/web_v4/dev_full.jsonl", as_jsonl(splits["dev"]))
        archive.writestr("data/web_v4/dataset_info.json", json.dumps(dataset, ensure_ascii=False, indent=2))
        archive.writestr("reports/data_report_v4.json", (ROOT / "data_report.json").read_bytes())
    with ZipFile(DEST) as archive:
        assert archive.testzip() is None
        assert not any("test.jsonl" in name for name in archive.namelist())
    sha = hashlib.sha256(DEST.read_bytes()).hexdigest()
    print(json.dumps({"archive": str(DEST), "bytes": DEST.stat().st_size, "sha256": sha,
        "train": len(splits["train"]), "dev_small": len(dev), "dev_full": len(splits["dev"]),
        "test_kept_local": len(splits["test"]),
        "dev_small_by_source_and_label": {"/".join(k): min(20, len(v)) for k, v in sorted(groups.items())}},
        ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
