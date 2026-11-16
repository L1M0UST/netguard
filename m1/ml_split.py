"""官方数据集请求指纹分组切分：训练/校准/测试三集隔离（60/20/20，确定性）。

分组键 = 去掉 timestamp/src_ip/dst_ip 后的请求组合哈希（method|url_path|request_body|user_agent）。
同一请求组合的全部行必须落在同一 split，防止近重复行跨集泄漏导致指标虚高；
随机行级切分（80/20）会混入训练样本，不能作为提升证据。
"""
from __future__ import annotations

import csv
import random
from pathlib import Path

from m1.ml_features import fingerprint_of_request

SPLIT_NAMES = ("train", "calib", "test")


def read_official_rows(path: Path) -> tuple[list[str], list[dict]]:
    """读取官方 xlsx：返回 (原始表头, 行字典列表)。真值列保持原表头名，由读取方隔离。"""
    from openpyxl import load_workbook

    from m1.run import is_ground_truth_header  # 延迟导入避免加载整条 M1 管线

    workbook = load_workbook(path, read_only=True, data_only=True)
    try:
        rows_iter = workbook.active.iter_rows(values_only=True)
        headers = [str(value or "").strip() for value in next(rows_iter, ())]
        label_indexes = [i for i, field in enumerate(headers) if is_ground_truth_header(field)]
        if len(label_indexes) != 1:
            raise ValueError(f"期望恰好一个真值列，实际找到: {label_indexes}")
        rows: list[dict] = []
        for values in rows_iter:
            if values is None or all(value is None for value in values):
                continue
            rows.append({headers[i]: values[i] for i in range(min(len(headers), len(values)))})
        if not rows:
            raise ValueError("数据集为空")
        return headers, rows
    finally:
        workbook.close()


def truth_of(row: dict, headers: list[str]) -> str:
    """取真值列文本（read_official_rows 已保证唯一真值列）。"""
    from m1.run import is_ground_truth_header

    for field in headers:
        if is_ground_truth_header(field):
            return str(row.get(field) or "").strip()
    raise ValueError("行中缺少真值列")


def split_rows(rows: list[dict], ratios: tuple[float, float, float] = (0.6, 0.2, 0.2),
               seed: int = 42) -> tuple[dict[str, list[dict]], dict]:
    """按请求指纹分组确定性切分；组整体归入当前行数缺口最大的 split。"""
    if abs(sum(ratios) - 1.0) > 1e-6 or any(r < 0 for r in ratios):
        raise ValueError("ratios 必须非负且和为 1")
    groups: dict[str, list[int]] = {}
    for index, row in enumerate(rows):
        groups.setdefault(fingerprint_of_request(row), []).append(index)
    keys = sorted(groups)
    random.Random(seed).shuffle(keys)
    total = len(rows)
    targets = dict(zip(SPLIT_NAMES, ratios))
    fill = {name: 0 for name in SPLIT_NAMES}
    buckets: dict[str, list[int]] = {name: [] for name in SPLIT_NAMES}
    for key in keys:
        best = max(SPLIT_NAMES,
                   key=lambda name: (targets[name] * total - fill[name], -SPLIT_NAMES.index(name)))
        buckets[best].extend(groups[key])
        fill[best] += len(groups[key])
    singleton_groups = sum(1 for indexes in groups.values() if len(indexes) == 1)
    stats = {
        "rows": total,
        "groups": len(groups),
        "duplicate_rows_from_repeated_groups": total - len(groups),
        "singleton_groups": singleton_groups,
        "seed": seed,
        "ratios": list(ratios),
        "group_key_fields": ["method", "url_path", "request_body", "user_agent"],
    }
    return ({name: [rows[i] for i in sorted(indexes)] for name, indexes in buckets.items()}, stats)


def write_split_csv(rows: list[dict], headers: list[str], path: Path) -> None:
    """写出 split CSV（保留原始表头含真值列；M1 摄入时按 is_ground_truth_header 剥离）。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({field: ("" if row.get(field) is None else row.get(field)) for field in headers})


def label_distribution(rows: list[dict], headers: list[str]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for row in rows:
        label = truth_of(row, headers)
        dist[label] = dist.get(label, 0) + 1
    return dict(sorted(dist.items(), key=lambda item: -item[1]))
