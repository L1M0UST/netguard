from __future__ import annotations

import push_all

push_all.FILES=[(name,name) for name in (
    'evaluate_mist_vllm.py','compare_mist_vllm.py','compare_qwen_mist_vllm.py',
    'export_mist_vllm.py','preserve_mist_checkpoints.py','wait_mist_after_qwen.sh',
)]

if __name__=='__main__':
    push_all.main()
