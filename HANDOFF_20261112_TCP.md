# StarryNet 项目交接：全量 TCP 卫星仿真轨迹

交接快照：2026-11-12 11:08 左右，Asia/Shanghai。运行持续变化，新对话先刷新状态。

## 目标与已确定的取舍

通过 StarryNet，把地面 Fiber 时间戳/方向轨迹重放成动态卫星网络中的客户端应用事件轨迹。主交付是 6000 条 TCP 仿真轨迹、地面源轨迹与输出的一一对应清单、冻结运行参数。不是重新浏览网页或真实 Starlink 采集。

用户已明确：减少对交付无直接帮助的验证和测试；跳过人为恢复突发顺序后再看分类的试验；暂停 DF 评估及误判归因；直接做全量 TCP，不再跑新的 50 条试验。实际观测到的方向交错、时延和突发变化保留到输出。

此前通常由用户手动运行实验，但本轮用户明确授权 `luna_worker` 执行全量任务，任务已经启动。新对话不要重复启动。

## 当前运行状态（实时核对结果）

- 6000 条计划生成成功，初始为 9 个会话；预检已通过，预检成功时间为北京时间 2026-11-12 10:52:18 左右。
- 正式 `run` 进程仍存在。attempts 日志当前记录 **31 个不同样本 success，0 条失败记录**；这是已落盘的进度，不是最终完成数。
- `session-0001` 在准备样本 `28-55` 前触发自动换会话：`GS26 satellite route unavailable after 120s: route does not use a GS26 satellite interface`。该会话 summary 状态 `rollover_required`，`worker_errors=[]`。
- 清单新增 `recovery-20261112T030653_998976Z`，`recovery_of=session-0001`。清单现在有 10 个会话条目，包含原会话和替代会话；**不能直接累加 samples/used_seconds 当成独立样本数或实际剩余时长**。使用现有 active_sessions/成功 ID 逻辑。
- 正式 manifest 顶层仍显示 `preflight_passed`，因此不能只凭顶层状态判断是否正在运行。需要结合进程、日志和 attempts。
- 当前尚无正式 `verification.json` 或 `dataset_manifest.json`；全量尚未验证或导出完成。

## 必要位置

仓库：`/home/shy/Project/StarryNet`

源轨迹：`/home/shy/Project/StarryNet/dataset/tor_fiber`，6000 条，75 类 × 80 次。

正式根目录：`/mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112`

正式 manifest：
`/mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112/runs/20261112T024712_468970Z/manifest.json`

总日志：
`/mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112/orchestrator.log`

计划输出：正式根目录的 `plan.json`。

计划中的最终输出：
`/mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112/dataset/tor_satellite_replay_tcp`

tmux 会话/窗口：`starrynet:e-v4-manual-check`（窗口 ID `@26`，当前索引 13）。用户要求只保留最后一个窗口，已将原正式任务 pane `%57` 移到该窗口，其余 13 个窗口已关闭；原仿真进程保持运行。

Python：`/home/shy/anaconda3/envs/starrynet/bin/python`，conda `starrynet`。

持久运行驱动：`/tmp/starrynet_formal_tcp_20261112.sh`。它在 tmux 中顺序执行 plan → preflight → run → finalize，前一步失败即停止；不要重新运行这个驱动，因为它会重新 plan。finalize 内部已调用 verify。

已固定参数：TCP、关闭 NAT、星间/星地链路各 1% 丢包、speed=1、seed=2025、session_seconds=9000、guard_seconds=0.5。切换规则不变。不要在运行中修改源轨迹、重放脚本或 StarryNet 代码：manifest 冻结了代码和输入哈希。

## 新对话的接续步骤

1. 只读查看 tmux、正式日志尾部和 attempts。确认是否仍有对应 run 进程，查看恢复会话是否继续推进。不启动第二个重放进程。
2. 若仍在运行，报告最新成功 ID 数和实际阶段，等待原任务继续。正在自动换会话不等于需要手动重启。
3. 若驱动停止，先找总日志中的 `FAILED stage=...` 以及对应 session summary；不要清理现场，不改历史哈希，不重做整批。可恢复中断使用同一 manifest 的 `run --resume`；仅在确认原 run 已结束后启动。
4. 原驱动仍活跃时会自动 finalize。若是手动 resume 成功，需手动执行 finalize；不要再单独重复 verify。
5. 最终交付要求：6000 个不同源 ID 与 6000 个成功导出 ID 一一对应，标签/哈希可追溯，内置收发校验通过。以 finalized manifest、verification 和 dataset_manifest 为完成证据，不能以 preflight_passed 或进程退出代替。
6. 用户没有要求本轮训练或分类评估。生成数据后先交付轨迹与配对清单。

查看进度（只读）：

```bash
tmux attach -t starrynet
# 或直接查看日志
tail -n 60 /mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112/orchestrator.log
```

仅确认原进程停止且属于可恢复中断时：

```bash
cd /home/shy/Project/StarryNet
source /home/shy/anaconda3/etc/profile.d/conda.sh
conda activate starrynet
PY=/home/shy/anaconda3/envs/starrynet/bin/python
MANIFEST=/mnt/HDD4T/shy/StarryNet_E_v4/formal_tcp_no_nat_20261112/runs/20261112T024712_468970Z/manifest.json
# 应在独立 tmux 窗口执行，并把输出留到新的 resume 日志，避免覆盖原日志。
"$PY" tools/replay_trace_over_starrynet.py run --manifest "$MANIFEST" --resume
# 仅在 run 成功后执行：
"$PY" tools/replay_trace_over_starrynet.py finalize --manifest "$MANIFEST"
```

## 已完成的工作及历史产物

- 已实现 UDP → TCP 重放，并修正初始/动态新增 Docker 链路关闭 NAT 的行为；补了路由、TCP 状态和收发诊断。当前 TCP 50 条试跑全部成功，已导出。
- 已完成 TCP 50 条的时序对照及 `18-8` 切换诊断，后续暂停扩展诊断。
- 既有全量 UDP：`/mnt/HDD4T/shy/StarryNet_E_v4/artifacts/e_replay_v4/20261013T154428_085732Z`，6000 条 finalized；输出 `/mnt/HDD4T/shy/StarryNet_E_v4/dataset/tor_satellite_replay_v4`。留作历史版本，不与 TCP 混合。
- 已导出 TCP 50 条：`/mnt/HDD4T/shy/StarryNet_E_v4/pilot_tcp_no_nat_20261111/runs/20261111T032636_222983Z`；输出根目录 `pilot_tcp_no_nat_20261111/dataset/pilot`。
- 后续 TCP 状态、零丢包及切换配对属于诊断批次，不能把 run_completed 当作已正式导出。
- 不沿用早期 319 小时的 UDP 历史估计来预测本轮 TCP；当前有自动恢复会话，实际完成时间需按最新推进估计。

## 已完成但暂停的 DF 工作

报告：`/home/shy/Project/StarryNet/artifacts/reports/wf_model_data_audit_20261111/README.md`

评估入口：`/home/shy/Project/StarryNet/tools/evaluate_replay_df.py`；环境 `/home/shy/anaconda3/envs/WFlib1/bin/python`。

冻结模型为 WFlib `tor_clean_3seed/tor_fiber/DF/seed_42.pth`，75 类、前 5000 个方向事件。TCP pilot 50 条中 train=40、valid=6、test=4；全 50 条原始准确率86%，重放68%，预测一致率80%；4 条 test 前后均100%，只覆盖两类。均不能当成全量独立测试结论。

新增9条错判的离线方向诊断已完成，目录：
`/home/shy/Project/StarryNet/artifacts/reports/wf_model_data_audit_20261111/direction_error_audit_20261112`

事件计数完整，方向交错和长下行突发发生变化；不能仅凭该相关性下因果结论。用户已决定跳过进一步突发恢复试验。先前计划中的“25类×2条测试子集”未实施，已被全量生成计划取代。

## 工作区注意事项

存在以下未提交工作，全部需要保留；不要 reset/clean/stash 或用历史版本覆盖：

已修改：`starrynet/local.py`、`starrynet/sn_observer.py`、`starrynet/sn_orchestrater.py`、`tools/e_replay_agent.py`、`tools/replay_trace_over_starrynet.py`、`tools/test_replay_trace_over_starrynet.py`。

新增：`tools/compare_replay_timing.py`、`tools/diagnose_replay_routes.py`、`tools/evaluate_replay_df.py`、`tools/replay_handover_pair.py` 及对应测试文件。

本轮用户授权 `luna_worker` 执行；原子智能体名称 `/root/tcp_full_handoff`。新对话的智能体可能无法复用原子智能体，运行事实以 tmux、磁盘日志和进程为准。

输出磁盘在启动时约剩315GB，现有脚本自带空间检查；不擅自删除历史数据。运行期间不新增对照实验、不修改切换策略、不为了分类分数挑选生成样本。
