# E_v4 重放最小复现说明

此分支从原始 StarryNet `03c18f5` 建立，重放流程取自 `8fc2c9a`，只迁入本实验需要的本地执行和运行可靠性修复。新计划、运行记录和数据都写入
`/mnt/HDD4T/shy/StarryNet_E_v4/repro_03c18f5/`；旧 manifest、历史数据和实验记录不作为输出目标。

## 固定协议

- Fiber 输入：`dataset/tor_fiber`，75 类 × 80 条，共 6,000 条；种子 `2024`，速度 `1`。
- 动态拓扑：25 颗卫星、GS26 和 GS27 两个地面站；高度 550 km，更新间隔 10 秒；卫星和地面站链路均为 5 Gbit/s、配置丢包 1%。
- 轨迹事件由 GS26 发出或接收：`+1` 从 GS26 发往 GS27，`-1` 从 GS27 返回 GS26；UDP 报文负载 512 B，端口 `19999/20000`。两端准备好后共用未来启动时刻。
- 输出按 GS26 的实际发送/接收记录生成；PCAP 在 GS26 的 `any` 接口抓取，以覆盖地面站切换。动态网络的丢包和调度允许有差异，因此不要求轨迹字节一致。
- 试运行：类别 `0、18、37、56、74`，每类 10 条，共 50 条，会话 900 秒；正式运行：6,000 条，会话 9,000 秒。
- 输出分别发布到 `dataset/tor_satellite_replay_v4_pilot/` 和 `dataset/tor_satellite_replay_v4/`。

## 改动清单

| 文件 | 改动及用途 | 离线验证 |
|---|---|---|
| `tools/replay_trace_over_starrynet.py` | 迁入 plan/preflight/run/verify/finalize 和 `run --resume`；默认输出隔离到新根目录；默认正式会话改为 9,000 秒，试运行默认 900 秒；manifest 对重放器、agent 和全部 StarryNet 运行文件记录 SHA-256；verify 汇总方向事件、丢失比例和单向输出。 | 计划/哈希/协议单元检查；verify 汇总单元检查。 |
| `tools/e_replay_agent.py` | 迁入双端 UDP 事件调度、准备确认、共同未来启动和实际观察记录。 | 报文头、事件方向和 agent 离线测试。 |
| `tools/audit_trace_domains.py` | 迁入只读轨迹审计器，检查文件覆盖、时间戳、方向与输入哈希。 | 审计器语法检查；运行步骤提供实际输入审计命令。 |
| `starrynet/sn_synchronizer.py` | 只增加可选 `local`、`argv` 参数，保留原构造参数顺序；停止时先通知并等待拓扑调度线程，再清理资源。 | 原构造接口签名、清理顺序及异常传播检查。 |
| `starrynet/sn_utils.py` | 按明确配置文件解析，并将 CLI 参数限制在显式 `argv`；按节点编号排序容器并等待全部就绪；检查网络命令错误；动态切换双向 GSL 时完整重设 qdisc，保留带宽和丢包参数。 | 配置隔离、节点排序、就绪等待和 GSL 参数检查。 |
| `starrynet/sn_orchestrater.py` | 将延迟更新改为完整替换 qdisc，同时保留原有 jitter、distribution、loss、rate、limit；清理命令允许已消失资源，并检查工作线程异常。 | qdisc 参数保留、资源清理和工作线程检查。 |
| `starrynet/sn_thread.py`、`starrynet/local.py` | 增加工作线程异常回传，以及 SSH/SFTP 形状的本地执行适配器。 | 异常传播、离线兼容测试；未启动 Docker 仿真。 |

保持原始轨道计算、节点/链路创建、路由及动态拓扑流程。没有迁入 Browser/Tor、GRE/NAT、自定义链路配置或通用回调扩展。`StarryNet` 原有前四个构造参数不变，`local=False`、`argv=None` 为可选参数。

## 环境与启动前检查

在已有的 `starrynet` tmux 会话里操作，不要另开第二个采集会话：

```bash
tmux has-session -t starrynet
tmux attach -t starrynet
```

进入会话后执行：

```bash
cd /home/shy/Project/StarryNet
conda activate starrynet
git branch --show-current
python --version
python -c 'import numpy, paramiko, requests'
command -v docker
command -v tshark || command -v tcpdump
docker info --format '{{.Swarm.ControlAvailable}}'
```

分支应为 `codex/e-v4-minimal-repro`，Docker Swarm manager 检查应输出 `true`。运行前确认没有重放进程或未清理的 StarryNet 资源；若以下任一命令列出内容，先检查并处理现有实验，不要启动第二份：

```bash
pgrep -af '[r]eplay_trace_over_starrynet.py.*(preflight|run)' || true
docker service ls --format '{{.Name}}' | grep -x constellation-test || true
docker ps -aq --filter label=com.docker.swarm.service.name=constellation-test
docker network ls -q --filter label=starrynet.owner=constellation-test
```

重放器还会对同一 manifest 加独占运行锁，并在会话开始时检查这些 StarryNet 资源。不要手动删除不明资源或覆盖非空输出目录。

## 输入审计

```bash
OUT=/mnt/HDD4T/shy/StarryNet_E_v4/repro_03c18f5
RUN_ROOT="$OUT/artifacts/e_replay_v4"
mkdir -p "$OUT/artifacts/reports"
python tools/audit_trace_domains.py \
  --domain F=/home/shy/Project/StarryNet/dataset/tor_fiber \
  --output "$OUT/artifacts/reports/fiber_input_audit.json" > /dev/null
python -c 'import json; p="/mnt/HDD4T/shy/StarryNet_E_v4/repro_03c18f5/artifacts/reports/fiber_input_audit.json"; r=json.load(open(p))["domains"]["F"]; assert r["valid"] and r["sample_count"] == 6000 and len(r["class_counts"]) == 75 and set(r["class_counts"].values()) == {80}; print("input audit passed:", r["sample_count"], "samples;", len(r["class_counts"]), "classes")'
```

审计不修改输入。如果审计不通过，不要继续 plan。

## 动态预检与 50 条试运行

先建立试运行计划。plan 是离线步骤，不会创建仿真容器：

```bash
python tools/replay_trace_over_starrynet.py plan \
  --input /home/shy/Project/StarryNet/dataset/tor_fiber \
  --run-root "$RUN_ROOT" \
  --dataset-output "$OUT/dataset/tor_satellite_replay_v4_pilot" \
  --seed 2024 --speed 1 --session-seconds 900 --pilot \
  | tee /tmp/e_v4_pilot_plan.json
MANIFEST=$(python -c 'import json,sys; print(json.load(sys.stdin)["manifest"])' < /tmp/e_v4_pilot_plan.json)
test -f "$MANIFEST"
```

确认 plan 输出 `sample_count: 50` 后，运行动态预检。它从输入中选三条双向轨迹，检查拓扑变化、切换、卫星路由、抓包和清理：

```bash
python tools/replay_trace_over_starrynet.py preflight --manifest "$MANIFEST"
```

预检通过后才运行试运行：

```bash
python tools/replay_trace_over_starrynet.py run --manifest "$MANIFEST"
```

若运行中断，确认没有同一实验仍在运行后，用原 manifest 续跑：

```bash
python tools/replay_trace_over_starrynet.py run --manifest "$MANIFEST" --resume
```

验收通过才发布试运行数据：

```bash
python tools/replay_trace_over_starrynet.py verify --manifest "$MANIFEST" \
  && python tools/replay_trace_over_starrynet.py finalize --manifest "$MANIFEST"
```

`verify` 输出并写入 `verification.json`：逐样本状态、双向观测事件总数、单向输出样本及编号、上行/下行丢失数和“已发送报文中的丢失比例”。单向轨迹和丢失比例单独报告，不将流水线通过解释为真实 Starlink 保真。

## 6,000 条正式运行

试运行通过并发布后，重新建立正式计划；不要把 50 条 pilot manifest 用于正式运行：

```bash
python tools/replay_trace_over_starrynet.py plan \
  --input /home/shy/Project/StarryNet/dataset/tor_fiber \
  --run-root "$RUN_ROOT" \
  --dataset-output "$OUT/dataset/tor_satellite_replay_v4" \
  --seed 2024 --speed 1 --session-seconds 9000 \
  | tee /tmp/e_v4_formal_plan.json
MANIFEST=$(python -c 'import json,sys; print(json.load(sys.stdin)["manifest"])' < /tmp/e_v4_formal_plan.json)
test -f "$MANIFEST"
```

确认输出 `sample_count: 6000`，并且样本覆盖为 75 类 × 80 条。接着按相同顺序完成动态预检、正式运行和验收：

```bash
python tools/replay_trace_over_starrynet.py preflight --manifest "$MANIFEST"
python tools/replay_trace_over_starrynet.py run --manifest "$MANIFEST"
```

中断后仍使用这个正式 manifest 续跑：

```bash
python tools/replay_trace_over_starrynet.py run --manifest "$MANIFEST" --resume
```

全部样本完成且 `verify` 通过后才发布：

```bash
python tools/replay_trace_over_starrynet.py verify --manifest "$MANIFEST" \
  && python tools/replay_trace_over_starrynet.py finalize --manifest "$MANIFEST"
```

`finalize` 会再次运行 `verify`，然后把样本复制到正式数据目录并写入 `dataset_manifest.json`。保留 run 目录下的 manifest、预检、会话 summary、PCAP、逐样本 evidence 和 verification 作为运行记录。

## 离线验证与未完成验收

已在现有 `starrynet` tmux 会话和 `starrynet` conda 环境完成离线检查：

- 重放测试：43 项通过，覆盖配置路径与参数隔离、原接口兼容、节点排序、容器就绪等待、线程异常传递、停止后清理、链路参数保留、输入/运行代码哈希拒绝变化、续跑参数、PCAP、方向和验收汇总。
- `py_compile`：重放器、agent、轨迹审计器、测试文件和 StarryNet 迁移运行文件通过。
- `git diff --check` 和 `plan --help` 检查通过。
- 使用实际 Fiber 输入生成了隔离在 `/tmp/e_v4_minimal_repro_actual_plan_20261104/` 的正式规模临时计划：6,000 条、75 类 × 80 条、种子 2024、速度 1、9 个会话、9,000 秒；每类覆盖 10 个时间分位，每个会话均在容量限制内。重新计算并核对了 6,000 条输入哈希、重放器/agent/配置/6 个运行文件哈希；计划输出目录未被创建。该步骤没有创建 Docker 仿真容器。

离线检查不证明容器内网络、实时切换或轨迹保真。

仍需手动完成：三条双向轨迹动态预检；50 条 pilot 的重放和 verify；正式 6,000 条重放、verify 和 finalize。验收报告需检查双向事件数、两个方向的丢失比例及单向输出情况。该实验是 StarryNet 上的固定 512 B UDP 轨迹重放，不等于真实 Starlink 测量，也不模拟浏览器、Tor 或 TCP 拥塞控制。
