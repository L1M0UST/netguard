# Qwen3-8B Web 单事件研判：第一阶段训练

更新时间：2026-11-16 17:00（北京时间）。记录当前作业与可复现配置；指标以实际生成的报告为准。
基座由 MiST-8B 切换为 Qwen3-8B；MiST 第一轮作业已停止（已下载 15.0/16.4 GB 的部分文件保留在服务器，未删除，可断点续传）。

## 服务器与资源

- 实例：`xn-a.suanjiayun.com`（SSH 网关，选 0 进入），容器 `f92cd603e2ac`，RTX 4090 24 GB，755 GB 内存，16 核。
- 数据盘 `/root/sj-tmp` 扩容至 69 GB（用户加 19 GB 后剩 30+ GB）；系统盘 `/` 为 overlay（临时层，最终产物需回传）。
- 工作目录：`/root/sj-tmp/cqsec_mist8b_web_20261115`（沿用原 MiST 工作目录名）。
- 环境已验证：Python 3.12.7、PyTorch 2.5.1/CUDA 12.4、LLaMA-Factory 0.9.4、Transformers 4.53.3、PEFT 0.16.0、bitsandbytes 0.45.5，GPU/BF16 可用。
- 旧 MiST 作业（download_model.sh、run_pipeline_v2.sh、report/export_monitor）已全部停止；实例重启时可能被平台侧自启动脚本拉起，需再次停止。

## 模型与数据

- 基座：ModelScope `Qwen/Qwen3-8B`，revision `26028140be3ee69b82b1d1450179ab71bb1121b9`，16,397,461,896 字节，16 个文件 SHA-256 全部校验通过（`reports/qwen3_download.json`）。
- 数据：`data/web_fit_v2`（与 MiST 第一轮同一份，标签来自数据源、未逐条人工复核）：
  - 训练 29,411 条（D0 比赛 7,697 + D1 Mendeley 21,714），10 类：正常访问 10,506、SQL注入 3,790、XSS 3,579、文件包含 3,450、远程命令执行 3,285、SSRF 2,001、目录遍历 767、Java反序列化 728、文件上传 702、CSRF 603。
  - 均衡验证子集 300 条（dev.jsonl）；封存测试集 6,537 条留在本机未上传。
- Qwen3 分词器长度复核（`audit_qwen_tokens.py`，`reports/qwen_token_audit.json`）：训练文本最大 1,835 token、均值 330、p99=822，**0 条超过 2,048 截断**；dev 提示词最大 763。

## 训练配置（configs/qwen3_round1.yaml）

QLoRA：4-bit NF4 双重量化；LoRA rank 16 / alpha 32 / dropout 0.05 / target all；BF16；梯度检查点。
学习率 5e-5，cosine，warmup 5%；batch 1 × 梯度累积 16（有效 16）；1 epoch ≈ 1,839 步；cutoff 2,048；template `qwen3_nothink`；eval 每 200 步（dev 300 条 loss）。
smoke（10 步，max_samples 64）已通过：loss 2.70 → 2.51，约 2.1–2.2 秒/步。

## 管线（run_qwen_stage1.sh，后台 PID 记录于 qwen_stage1.pid）

长度审计 → smoke → 基线评测（`evaluate_web.py`，dev 300，贪心 256 新 token，M1 四段契约）→ 正式 QLoRA 训练 → 适配器评测 → 前后对比（`compare_qwen_web.py`）→ 打包（`export_qwen_artifact.py` → `exports/qwen3-web-stage1.zip`）。
任一步失败即停；状态写入 `reports/qwen_stage1_state.txt`，日志在 `logs/qwen_*.log`。

### 已实测的性能参考

- 基线评测：约 15–16 秒/条（基座每条都生成满 256 token 的思考文本，输出以 `<tool_call>Bash<arg_key>command</arg_key><arg_value>sleep 480; cd "E:/platform_taishi/taishi_platform/training/mist8b_web" && python remote_client.py run _poll2.sh --timeout 45