"""一次性补丁：把 config.yaml 对齐统一工作区与 DeepSeek 配置。运行后可删除。"""
from pathlib import Path

path = Path(__file__).resolve().parent.parent / "config.yaml"
text = path.read_text(encoding="utf-8")
replacements = {
    "  inbox_subdir: 04_m2_inbox": "  inbox_subdir: m2_inbox",
    "  output_subdir: 05_m2_output": "  output_subdir: m2_output",
    "  status_subdir: 06_status/m2": "  status_subdir: m2_status",
    "  sqlite_path: workspace/06_status/m2/module2_state.db": "  sqlite_path: workspace/m2_status/module2_state.db",
    "  timeout_seconds: 30\n  max_retries: 2": "  timeout_seconds: 120\n  max_retries: 2",
    "  max_output_tokens: 2000": "  max_output_tokens: 4000",
    "      model: deepseek-chat": "      model: deepseek-v4-pro",
}
missing = [k for k in replacements if k not in text]
for old, new in replacements.items():
    text = text.replace(old, new)
path.write_text(text, encoding="utf-8")
print("patched, missing keys:", missing)
