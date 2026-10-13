# F/S/E 数据域审计摘要

审计时间：2026-10-13（Asia/Shanghai）。完整逐文件 JSON 见
[`trace_domain_audit_20261013.json`](artifacts/reports/trace_domain_audit_20261013.json)。
工具以 5 ms 作为小时间回退阈值；输入未被修改。

| 域 | 文件/样本 ID | 结构审计 | 小回退 | 大回退 | 内容 SHA-256 |
|---|---:|---|---:|---:|---|
| F `dataset/tor_fiber` | 6000 / 6000 | 通过 | 22,688 | 0 | `d691a5b34f4d4a51679c15904ec29e1242282cbcce37f120ff3706e4f76ace76f` |
| S `dataset/tor_starlink` | 6000 / 6000 | 通过 | 89,548 | 0 | `fee4492a10efc5262fae3053a2bb881e184fd6ea97bcd6e2060007c56c3d90aa` |
| E `dataset/tor_satellite` | 6000 / 6000 | 未通过 | 706 | 847,603 | `db37714042967890e879ee83f7b437acf63f3536d9f8d4a9ee3821db5a299981` |

三个域的文件名 ID 交集为 6000。F/S 的小回退应在预处理时按已冻结的非负 `dt`
策略处理；不能静默排序或删除事件。E 含秒级时间戳重置，且当前目录只有时间戳和方向，
因此不能把它当作新 P2/P3 生成物，也不能据此推断带宽、丢包、队列、TCP 重传或卫星切换。

## 协议与来源盘点

三域均表现为 75 个类别、每类 80 个文件，文件名只提供 `class-repeat`。在当前
StarryNet 仓库中没有找到与 F/S 对应的 URL/页面清单、浏览器和 Tor 版本、会话/日期
划分、原始 PCAP、Tor cell/IP 包定义或既有 train/valid/test manifest。因此，当前
6000 个 ID 交集只能证明文件名层面的对应，不能证明类别语义和采集协议可直接对齐。

仓库内的 `dataset/docker_starlink_sim_v3.py` 提供了 E 的可追溯线索：脚本声明以 F
目录为输入，使用 UDP 注入、`speed=10.0`，并在脚本注释中跳过动态 `start_emulation()`；
重建时只把收到的 label=1 包替换为接收时间，其他事件保留输入时间。这与 E 中的大时间
回退相符，但没有运行日志、页面来源或原始 PCAP 不能把脚本描述升级为完整来源证明。

另外只读核对了当前 SatLumen 数据处理实现（`data_process/convert_to_npz.py`、
`src/data/directional_count.py` 和 `configs/formal_frozen_directional_count.yaml`）：
原始输入先变为 `(N, 10000, 2)` 的 `[timestamp, signed_direction]`，不足零填充、超长
取前缀；独立分层划分为 81%/9%/10%，默认 seed 为 2024；DirectionalCount 再取前
5000 个事件，按原始 timestamp 在 120 秒/2700 bins 中计数，并把非单调事件作为诊断
计数。StarryNet 的转换工具现已提供这一 `satlumen_raw` 模式；此前的
`delta_direction` 仅保留为明确标注的审计表示。

因此当前可推进的是结构审计、E→E 工程管线和同语义预处理开发；E→S、F+E→S 以及
“75 类真实网站”解释仍是数据依赖未满足。启动真实域迁移前必须补齐页面/类别映射、
采集协议、划分清单和表示单位，或明确将结果限定为文件级统计比较。

这份审计是兼容性输入，不是分类性能结果。P2 严格回归和 P3 浏览器协议闭环现已
完成；但当前 E 目录仍因大时间回退未通过，开始 E→S 或 F+E→S 前仍需取得
语义兼容的 E 数据（或完成有界、可解释的表示修复），并锁定与 F/S 相同的
PCAP/序列预处理。
