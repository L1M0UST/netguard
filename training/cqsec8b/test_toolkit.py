"""Offline checks for leakage detection and metric denominators."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import check_sft_data as checker
import eval_d1
import prepare_d1_draft as prepare


def example(record_id: str, group: str, split: str, message: str, ref: str | None = None) -> dict:
    event = {"event_id": record_id, "message": message}
    return {"instruction": "return JSON", "input": json.dumps({"task_type": "demo", "events": [event]}),
            "output": json.dumps({"stages": [{"evidence_event_ids": [ref or record_id]}]}),
            "_meta": {"record_id": record_id, "source": "test", "group_id": group,
                      "label_status": "human_reviewed", "split": split}}


class ToolkitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = {"records": {}, "group_id": {}, "family_id": {}, "inputs": {}}
        self.report = {}

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name: str, row: dict) -> Path:
        path = self.root / name
        path.write_text(json.dumps(row) + "\n", encoding="utf-8")
        return path

    def test_group_leak_rejected(self):
        checker.check_file(self.write("train", example("a", "same", "train", "one")),
                           "train", False, self.registry, self.report)
        with self.assertRaisesRegex(ValueError, "spans train and dev"):
            checker.check_file(self.write("dev", example("b", "same", "dev", "different")),
                               "dev", False, self.registry, self.report)

    def test_identical_input_with_new_event_id_rejected(self):
        checker.check_file(self.write("train", example("a", "g1", "train", "same event")),
                           "train", False, self.registry, self.report)
        with self.assertRaisesRegex(ValueError, "identical instruction/input"):
            checker.check_file(self.write("dev", example("b", "g2", "dev", "same event")),
                               "dev", False, self.registry, self.report)

    def test_unknown_evidence_rejected(self):
        with self.assertRaisesRegex(ValueError, "event absent"):
            checker.check_file(self.write("train", example("a", "g1", "train", "x", "missing")),
                               "train", False, self.registry, self.report)

    def test_synthetic_smoke_rejected_for_formal(self):
        row = example("a", "g1", "train", "x")
        row["_meta"]["label_status"] = "synthetic_smoke"
        with self.assertRaisesRegex(ValueError, "unapproved label_status"):
            checker.check_file(self.write("train", row), "train", False, self.registry, self.report)

    def test_metrics_count_invalid_as_incorrect_and_report_abstentions(self):
        rows = [{"truth": "normal", "predicted_family": "invalid", "verdict": "invalid", "status": "error"},
                {"truth": "sql_injection", "predicted_family": "sql_injection", "verdict": "malicious", "status": "ok"}]
        scores = eval_d1.metrics(rows)
        self.assertEqual(scores["samples"], 2)
        self.assertEqual(scores["family_accuracy_all_samples"], 0.5)
        self.assertEqual(scores["normal_review_or_invalid_rate"], 1.0)

    def test_decoded_grouping_key(self):
        self.assertEqual(prepare.norm("%252fadmin"), "/admin")

    def test_evaluation_template_matches_llamafactory_no_think(self):
        prompt = eval_d1.build_prompt(None, "instruction\ninput", "lf_nothink")
        self.assertEqual(prompt, "<|im_start|>user\ninstruction\ninput<|im_end|>\n<|im_start|>assistant\n")

    def test_attack_only_cannot_report_normal_fpr(self):
        rows = [{"truth": "sql_injection", "predicted_family": "sql_injection",
                 "verdict": "malicious", "status": "ok"}]
        scores = eval_d1.metrics(rows)
        self.assertIsNone(scores["normal_flagged_malicious_rate"])
        self.assertIsNone(scores["macro_f1_six_classes"])


if __name__ == "__main__":
    unittest.main()
