# Qwen3-8B 下载测速

日期：2026-11-16，算力实例为 RTX 4090，数据盘 `/root/sj-tmp`。测速使用官方 [ModelScope Qwen/Qwen3-8B](https://www.modelscope.cn/models/Qwen/Qwen3-8B) 仓库，固定版本 `26028140be3ee69b82b1d1450179ab71bb1121b9`。完整模型文件共 16,397,461,896 字节。

32 MiB 的首分片短时请求得到约 15.0 MB/s。第一个完整权重分片实际下载 3,996,250,744 字节、耗时 185.0 秒，平均 21.6 MB/s，已通过 SHA-256 校验。

完整 16,397,461,896 字节下载及各文件校验总共用时 **749.9 秒（12 分 30 秒）**，按全量字节除以总耗时约 **21.9 MB/s**；总耗时包括清单和小文件下载、逐文件哈希校验，以及一次自动重试。全部 16 个文件的 SHA-256 已核对通过。另已用 Transformers 离线读取配置、分词器和 5 个 safetensors 索引，核对了 399 个张量的文件归属；尚未加载整个模型或进行推理测试。

同机 MiST-8B 在上述阶段约 2.2–2.5 MB/s，使用 Hugging Face 镜像下载；这是不同来源、不同文件的同时下载观察，结果反映网络和下载源差异，不代表模型推理或训练速度。

Qwen3-8B 全量下载位于服务器 `/root/sj-tmp/cqsec_mist8b_web_20261115/models/Qwen3-8B-ModelScope`，每个文件完成后与 ModelScope 清单中的 SHA-256 核对。它与当前正在等待 MiST 权重的训练任务分开，未改变第一阶段的基座。

实时检查命令：

```powershell
python 'E:\platform_taishi\taishi_platform\training\mist8b_web\remote_client.py' run 'E:\platform_taishi\taishi_platform\training\mist8b_web\status_two_models.sh' --timeout 30
```

服务器 `reports/qwen3_download.json` 记录了总耗时、版本和校验状态。该测速不涉及模型性能评测。
