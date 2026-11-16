from __future__ import annotations

import push_all

push_all.FILES = [(name, name) for name in ('export_qwen_adapter.py', 'wait_qwen_adapter_backup.sh')]

if __name__ == '__main__':
    push_all.main()
