# 外部公开安全题集抽样试跑

日期：2026-11-14（Asia/Singapore）。本次只做推理评测，没有训练。

## 配置与范围

- 模型：现有 cqsec v3.2，Qwen3-4B-Instruct-2507 微调后的 GGUF Q4_K_M。
- 权重 SHA-256：`d3d06614de247e748bf7719ab25bee13725c14cb8d66da30bdb6951b10c01fe6`。
- 硬件：RTX 4060 Laptop，8188 MiB 显存，驱动 596.36。
- 每套题集固定 seed=42 抽取 100 题；并发 4；temperature=0；最大新生成 token=512。
- CTI-MCQ 使用公开文件的 Prompt 列；CyberMetric 使用问题与四个选项构造单字母回答指令。
- 真值未放入模型输入。源文件哈希、抽样行号、逐条输出均已保存。
- 这是自定推理配置下的公开题集抽样结果，不是完整 benchmark 官方成绩，也不是未微调底座对照实验；本轮未审计其与历史 SFT 的近重复。

## 结果

| 题集 | 抽样数 | 严格格式答对 | 宽松解析答对 | 严格格式有效 | 推理墙钟耗时 | 请求失败 / 截断 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CTI-MCQ | 100 | 34 | 48 | 59 | 67.757 秒 | 0 / 0 |
| CyberMetric-500 | 100 | 91 | 91 | 100 | 6.461 秒 | 0 / 0 |

严格解析要求最后一个非空行是 A/B/C/D（容忍句点或右括号）。宽松解析另接受一个无歧义的 Answer/答案标记；它是诊断指标，不能直接替代其他项目的官方评分。未解析成功与请求失败均计为错误。

总耗时 80.298 秒，包含本地服务启动与题集获取。按本轮吞吐简单外推，CTI-MCQ 2500 题约 28.23 分钟，CyberMetric-500 全量约 0.54 分钟；实际全量需预留长度分布与吞吐变化空间。

较早的 run2 使用 64 个新生成 token，CTI-MCQ 有 87 条截断，因此仅用于诊断，不用其分数评价知识能力。本目录是增加输出预算后的复测。

## 产物

- `summary.json`：配置、来源、抽样索引、权重与预测文件哈希、汇总指标。
- `cti_mcq.predictions.jsonl`、`cybermetric_500.predictions.jsonl`：逐条真值、输出、两种解析结果、token 用量与耗时。
- `server.stdout.log`、`server.stderr.log`：隔离服务运行日志。
- 运行脚本：`E:/platform_taishi/taishi_platform/tmp/benchmark_probe_20261114.py`。

服务只监听本机隔离端口 18008，已在试跑结束后关闭本次启动的进程。

## 来源

- [CTIBench 作者仓库](https://github.com/maveryn/cti-bench)
- [CyberMetric 作者仓库](https://github.com/cybermetric/CyberMetric)
