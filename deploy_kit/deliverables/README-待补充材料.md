# 交付材料目录（deliverables）

本目录用于放置**参赛交付的对外材料**，与代码、模型分离，便于单独打包送审或
替换更新，从而避免每次改动都重新分发整个系统。

## 建议放置方式

```
deliverables\
├── 01_演示PPT\        答辩 / 演示用 PPT（.pptx、导出 PDF）
├── 02_技术文档\       技术文档、方案说明、测试报告（.docx / .pdf / .md）
├── 03_演示视频\       演示录屏、解说音视频（.mp4 等）
└── 04_其他材料\       报名表、承诺书、数据合规说明等
```

## 当前状态

各子目录已建好占位，等待补充材料。可参考现有素材（已随包附带在
`taishi_platform\docs\`）：

| 现有素材 | 位置 | 说明 |
|---|---|---|
| 答辩演示 PPT | `taishi_platform\docs\NetGuard-答辩演示.pptx` | 可复制到 `01_演示PPT\` |
| 技术文档（docx / pdf） | `taishi_platform\docs\` 下的 `*技术文档-NetGuard*.docx/pdf` | 可复制到 `02_技术文档\` |
| 演示视频操作流程与台词 | `taishi_platform\docs\NetGuard_竞赛演示视频操作流程与解说台词.docx` | 可直接作为录制脚本 |
| 赛前验证与复现说明 | `taishi_platform\docs\赛前验证与复现说明.md` | 验证/复现方法论 |
| 数据来源与 PCAP 边界 | `taishi_platform\docs\数据来源与PCAP边界.md` | 数据合规说明 |
| 验收测试指南 | `taishi_platform\docs\验收测试指南.md` | 现场演示步骤 |

## 注意

- 视频文件体积大，建议单独传输，不要与本包一起压缩（会显著增大分发体积）
- 材料中**不要出现任何 API Key、真实客户数据或未脱敏的个人信息**
- 演示录屏请使用纯本地模式（`DEEPSEEK_ENABLED=0`），避免录到密钥或额度提示
