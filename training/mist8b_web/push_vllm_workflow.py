"""Upload the new vLLM workflow over one checked gateway session."""
from __future__ import annotations

import push_all

push_all.FILES = [(name, name) for name in (
    'evaluate_qwen_vllm.py', 'compare_qwen_vllm.py', 'export_qwen_vllm.py',
    'wait_qwen_vllm.sh',
)]

if __name__ == '__main__':
    push_all.main()
