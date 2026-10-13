# F/S/E 数据审计与批处理接口

本目录中的工具只负责审计和编排，不自动启动仿真、浏览器或训练。统一域名为
`F`（真实 Fiber）、`S`（真实 Starlink）和 `E`（StarryNet 仿真）。没有协议和类别
对应证据时，不能把 E 标成 S。

## 数据兼容性审计

审计读取文件但不修改输入。默认检查 `dataset/tor_fiber`、
`dataset/tor_starlink` 和 `dataset/tor_satellite`：

```bash
python3 tools/audit_trace_domains.py \
  --output artifacts/reports/trace_domain_audit.json
```

报告验证文件名 `class-repeat`、两列 `timestamp direction`、有限且非递减的时间戳、
方向 `-1/+1`、完整样本 ID、每个文件的解析状态和域间 ID 交集，并保存精确内容哈希。
报告中的语义说明是审计结果的一部分：只有时间戳与方向时，不能据此推断带宽、丢包、
队列、TCP 重传或切换参数；现有 `tor_satellite` 目录也不会自动获得新 P2/P3 来源证明。

## 可恢复批处理

先准备页面清单，例如 `pages.json`：

```json
{
  "pages": [
    {"page_id": "class-000", "url": "http://...", "expected_marker": "..."}
  ]
}
```

生成 5 页面、每页 10 个独立样本的 pilot 清单：

```bash
python3 tools/batch_manifest.py plan \
  --pages pages.json \
  --output artifacts/batch/pilot/manifest.json \
  --domain E --repeats 10 --retry-limit 1
python3 tools/batch_manifest.py preflight \
  --manifest artifacts/batch/pilot/manifest.json
```

批处理器要求采集命令为一个 argv 模板，支持
`{sample_id}`、`{attempt_id}`、`{page_id}`、`{url}` 和 `{output_dir}` 占位符。采集命令
必须在最后一行输出 JSON 对象，并以 `artifacts` 列出相对于批次目录的文件及可选 SHA-256：

```bash
python3 tools/batch_manifest.py run \
  --manifest artifacts/batch/pilot/manifest.json \
  --command 'python3 my_collector.py --sample-id {sample_id} --attempt-id {attempt_id} --url {url} --output-dir {output_dir}'
```

中断后只能对同一 manifest 使用 `--resume`：已存在且通过文件存在性与哈希校验的成功样本
会跳过，损坏或失败样本生成新的 attempt ID；原始失败行永久保留，重试不增加独立样本数。

```bash
python3 tools/batch_manifest.py run \
  --manifest artifacts/batch/pilot/manifest.json \
  --command 'python3 my_collector.py --sample-id {sample_id} --attempt-id {attempt_id} --url {url} --output-dir {output_dir}' \
  --resume
python3 tools/batch_manifest.py verify \
  --manifest artifacts/batch/pilot/manifest.json
```

`verify` 要求每个计划样本恰好一个通过哈希校验的成功 attempt，同时报告失败、缺失、重复
ID 和额外记录。正式 75×80 批次只有在真实类别、页面来源和预处理语义已核对后才可生成。

## 序列预处理与预测评估

`prepare_trace_dataset.py` 默认按当前 SatLumen 的原始输入语义转换成
`(N, max_length, 2)`：第一列保留原始 timestamp，第二列是 `-1/+1` 方向，尾部零填充，
非 padding 的零 timestamp 按原实现写成 `1e-6`。`--representation delta_direction` 才
会输出从首事件开始的非负 `delta_seconds`，它是独立的统计审计表示，不能与 SatLumen
DirectionalCount 输入混用。超长样本默认报错；只有确认目标协议采用同样的前缀截断时才
显式传 `--truncate`。它不会自动创建训练划分；应传入已经核对过的 split manifest。
默认会拒绝 E 目录中的秒级回退，`--allow-large-reversal` 仅用于明确标记的审计转换。

```bash
python3 tools/prepare_trace_dataset.py \
  --domain F=dataset/tor_fiber \
  --domain S=dataset/tor_starlink \
  --split-manifest /path/to/locked_split.json \
  --max-length 10000 --truncate \
  --output artifacts/preprocessed/run-<id>
```

对当前历史 E 目录若只做明确标注的审计转换，必须单独运行并保留例外参数；这不构成
与 F/S 兼容的 E 数据：

```bash
python3 tools/prepare_trace_dataset.py \
  --domain E=dataset/tor_satellite --max-length 10000 --truncate \
  --allow-large-reversal --representation delta_direction \
  --output artifacts/preprocessed/audit-E-<id>
```

输出目录包含 `data.npz` 和记录表示、输入域哈希、回退数量、划分计数的
`manifest.json`。在确认新 E 数据通过域语义门槛前，不应对当前旧 E 目录使用强制大回退
转换。

训练代码保存逐样本 JSONL/CSV 预测后，用 `evaluate_predictions.py` 计算 Accuracy、
Macro-F1、每类结果和按 `domain/protocol/seed` 的样本标准差；它不选择 checkpoint，也不读取
目标测试集以外的训练状态。正式协议可显式要求 42、2024、2025 三个种子：

```bash
python3 tools/evaluate_predictions.py \
  --predictions artifacts/predictions/E_to_S.jsonl \
  --expected-seed 42 --expected-seed 2024 --expected-seed 2025 \
  --output artifacts/evaluation/E_to_S.json
```
