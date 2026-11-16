# Qwen3-8B Web 第一轮：当前作业

记录时间：2026-11-16 22:33（UTC+8）。这是一份启动记录，不是训练完成或效果报告。

## 当前事实

- MiST-8B 文件已下载并校验，已安排在 Qwen 的训练、vLLM 配对评测和打包完成后启动独立训练；它不能直接使用 Qwen 适配器。Qwen 评测失败时 MiST 排队任务会停住并记录状态。
- Qwen/Qwen3-8B（ModelScope 修订 `26028140be3ee69b82b1d1450179ab71bb1121b9`）的正式 QLoRA 已运行在单张 RTX 4090 上；训练集 29,411 条、1 epoch、1,839 个优化步。
- 训练配置：4-bit NF4、LoRA rank 16 / alpha 32、BF16 计算，单卡 batch 1、梯度累积 16，长度上限 2,048。
- 此前真实 10 步 QLoRA smoke 已完成；新正式训练启动时，模型文件和数据长度报告均通过检查。
- 2026-11-16 22:50 左右，正式训练完成第 200 步和首次开发集 loss 验证；`checkpoint-200` 已由独立保留程序复制，记录的 eval loss 为 0.03834。回答有模板成分，该损失不等于分类准确率。
- 之前的单条 Transformers 基线仅完成 176/300 条，没有完整报告；新对比不会混用旧结果。
- 训练和 vLLM 使用独立虚拟环境。训练在 `/root/sj-tmp/cqsec_mist8b_web_20261115/env312`，vLLM 安装至系统盘 `/root/qwen3-vllm-085`。vLLM 0.8.5 的依赖检查、Qwen3 架构注册、LoRA 接口和关闭思考模板的 CPU 检查已通过。使用随机初始化的极小 Qwen3 模型及其 LoRA，真实 GPU 的基座生成、LoRA 加载，以及评测脚本的成对输出与汇总检查也已通过；正式 8B 模型尚未进行 vLLM 推理。

## 自动后续步骤

1. Qwen 训练结束后，独立后台任务打包 LoRA 适配器、配置和训练记录，并生成 SHA-256；该备份不依赖 vLLM 成功。
2. 训练进程结束、GPU 释放、vLLM 安装完毕后，评测任务才会启动，并先做真实适配器加载检查。
3. 300 条均衡验证样本使用相同官方 no-thinking 提示词、相同 BF16 vLLM 和解码设置，比较原始 Qwen 和 QLoRA；再按来源和类别抽取 75 条，使用 SFT 模板做配对补充检查。
4. 基线和适配器报告分别保留逐样本结果、分类指标、正常样本误报、输出格式和生成结束原因。生成失败或无法识别的样本不会从分母剔除。
5. 原始数据源标签尚未逐条人工复核；以上属于开发验证，不是封存测试或完整系统验收。Qwen 的基座文件未被微调覆盖，因此可以训练之后再对无适配器的原始基座进行成对评测。
6. Windows 本机后台监控会在电脑与网络可用时，将完成的权重备份和评测包下载到 `E:\platform_taishi\mist8b-web-data` 并比对 SHA-256。机器关闭或休眠期间不能保证自动下载；云端独立任务仍以实际实例状态为准。
7. 训练的周期性检查点在被自动轮换前会额外保存 LoRA 权重、适配器配置和训练状态，便于后续评估早期版本；这些副本不含优化器，不能作为完整断点续训文件。验证损失仅作参考，不能代替独立分类测试。
8. Qwen 完成后先对 MiST 做真实 5 步 QLoRA smoke，通过后才开始相同数据的 1 epoch 正式训练；独立打包适配器，然后在相同验证集和 vLLM 参数下分别评测 MiST 基座和 MiST 适配器，并生成 Qwen/MiST 四列对比。本阶段尚未实际训练 MiST，也尚未获得任何 8B vLLM 测评指标。

## 文件和状态

- 本机状态：`E:\platform_taishi\mist8b-web-data\qwen3-vllm-status.txt`
- 云端工作目录：`/root/sj-tmp/cqsec_mist8b_web_20261115`
- 训练日志：`logs/qwen3_round1.log`；训练状态：`reports/qwen_round1_now_state.txt`
- vLLM 安装日志：`logs/vllm_install.log`；安装状态：`reports/vllm_install_state.txt`
- 后续评测状态：`reports/qwen_vllm_pipeline_state.txt`；评测日志：`logs/qwen_vllm_evaluation.log`
- 自动备份状态：`reports/qwen_adapter_backup_state.txt`
- 检查点保留状态：`reports/qwen_checkpoint_monitor_state.txt`；清单：`reports/qwen_preserved_checkpoints.json`
- 计划产物：`exports/qwen3-web-stage1-adapter.zip`、`exports/qwen3-web-stage1-vllm.zip`（实际出现且校验通过后才算产出）。
- MiST 队列状态：`reports/mist_after_qwen_state.txt`；本机状态：`E:\platform_taishi\mist8b-web-data\mist8b-vllm-status.txt`。
