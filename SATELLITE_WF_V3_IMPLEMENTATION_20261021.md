# 网站指纹卫星流量仿真 V3：实现与准入状态

更新：2026-10-22。V3 以单独协议 ID `starrynet-browser-tor-route-nat-v3` 和域名 `E_BROWSER_TOR_V3` 开始。现有 V1/V2 目录、冻结文件、账本和样本不纳入 V3，也不做在线续采。V3 固定对象 GRE/NAT 网络验收已于 2026-10-21 通过，run ID 为 `20261021T213558_089229Z`。

## 当前实现

- `protocols/satellite_wf_v3/runtime_config.json` 冻结 V3 网络、方向链路参数、时间捕获、试采预算及训练门槛。5 Gbit/s、零丢包是工程基线假设；没有真实链路标定。
- 同一配置声明无卫星、静态卫星、动态无切换、动态跨切换四个固定对象验证场景；前两个只作网络控制，不允许训练准入。未知参数只能放入命名的 `sensitivity_profiles`，并显式保持 `scientific_calibration: false`。
- `starrynet/sn_link_profile.py` 与 StarryNet 初始化/更新链路接口支持方向独立的速率、附加单向时延、抖动、丢包和队列上限。物理轨道传播时延继续由 StarryNet 拓扑矩阵计算，附加时延叠加在其上；动态建链和传播时延更新继续应用同一个冻结 profile。
- 使用 V3 profile 时，StarryNet 逻辑秒按单调时钟绝对节拍调度，并写入 `simulation_clock.jsonl`，逐条对应 UTC、单调时间、计划节拍与调度滞后；旧协议仍使用既有调度路径。
- `tools/satellite_wf_v3_route_nat.py` 提供 GRE + GS27 NAT 的计划、StarryNet `constellation-test` 容器内安装、路由检查与按本次变更逐项恢复。GRE 接口 `wf-gre0` 是稳定捕获点；GS26 公网默认路由及固定对象 `/32` 路由经 GRE，GRE 外层端点取两端当前卫星路由选出的接口源地址，GS27 公网出口限定为 `B27-default`。验收拓扑中外层端点为 `9.1.7.60` 和 `9.2.13.60`；GS26 IPv6 在隔离网络命名空间内临时禁用并在收尾时恢复，避免旁路。安装和恢复会先核实容器属于该 StarryNet 服务。
- [`V3 固定对象网络验收报告`](artifacts/reports/satellite_wf_v3_20261021/network_acceptance/20261021T213558_089229Z/REPORT.md) 与 [`机器可读验收摘要`](artifacts/reports/satellite_wf_v3_20261021/network_acceptance/20261021T213558_089229Z/summary.json) 记录了通过结果和 PCAP 哈希。三次 1 MiB HTTP 200 的对象 SHA-256 均为 `c8411639cfd76fea51e53e9fdbc6c8cc13224e48aee23b20312040c10072aeef`；GS26/GRE、GS27/GRE、GS27/B27-default 及两端 GRE 外层抓包均通过，内核丢包计数为零，Docker 基线已恢复。
- `tools/satellite_wf_v3.py` 提供配置校验、F/S 来源证据校验和样本训练准入检查。准入依据来源文件哈希、类别映射、采集契约、每条样本的门槛和会话分组划分。
- 离线实现和来源准入记录、后续固定对象网络验收补记见 [`VALIDATION.md`](artifacts/reports/satellite_wf_v3_20261021/VALIDATION.md)；机器可读的 F/S 来源准入审计见 [`source_audit.json`](artifacts/reports/satellite_wf_v3_20261021/source_audit.json)。

## 当前准入与未完成事项

用户已确认当前 F/S 就是目标 Spacesec2024 数据集，并授权解除训练来源门禁。系统按用户确认把类别 0–74 映射到论文附录 A 的同序网站，来源审计状态为 `user_attested_with_unresolved_semantics`，机器结果见 [`source_audit.json`](artifacts/reports/satellite_wf_v3_20261021/source_audit.json)，确认记录见 [`dataset_identity_attestation.json`](artifacts/reports/satellite_wf_v3_20261021/dataset_identity_attestation.json)。本机 F/S trace 与本机分域归档逐文件哈希一致，但这些归档仍未与 Zenodo `WFdata75x80.zip` 做字节级校验。

门禁解除不等于八项原始采集语义已知。浏览器/Tor 版本、缓存与访问动作、抓包点/过滤、事件单位、原始方向、时间起点、访问窗口和 session 来源仍作为 16 条域级 caveat 写入报告；这批数据可以按用户授权进入训练，但结论必须披露这些限制，不能据此声称 StarryNet 数据复现真实 Starlink。

V3 GRE/NAT 固定对象网络工程验收已完成。V3 Browser/Tor collector 尚未接入，因此网站访问采集和样本级 manifest 检查仍未完成；没有创建 V3 样本，也没有启动训练。验收报告明确 `scientific_fidelity_verified=false`、`training_data_eligible=false`；该工程通过不能解释为真实 Starlink 保真或训练数据准入。

## 之前踩过的坑

| 现象 | 保存证据 | V3 做法 |
|---|---|---|
| UDP 事件重放被说成真实网站流量 | E_v4 固定 512 B UDP，不含浏览器、Tor、TCP 拥塞反馈 | 只作网络功能诊断；训练候选由真实浏览器访问产生 |
| 代理监听但 CONNECT/TLS 不通 | V1.4 的 94 个失败中 91 个拒绝连接；V2.2 在 TLS CONNECT 超时后暂停 | 分开预检监听、CONNECT、TLS、Tor bootstrap、目标访问；基础设施故障暂停且不消耗站点重试 |
| 代理链改写连接语义 | Tor 随机 SNI 的历史诊断；旧采集 relay 终止并重建 TCP | 主路径取消应用 relay；使用 GRE 转发并在 GS27 做 L3 NAT，保留 Tor 到中继的端到端 TCP |
| 固定完整 Tor 路径让验证失真 | 固定 middle relay 曾不可用 | 仅固定入口 bridge，实际 middle/exit 由 Tor 选择并记录；完整路径固定只用于诊断 |
| 代码/审计规则版本不一致 | canonical URL 检查拒绝站内跳转；合法四端点 offload 曾误判 | V3 独立协议；现有 auditor 与 V2 账本不覆盖 |
| TSO/GSO 改变事件粒度 | 已审计到超 MTU 聚合包，关闭卸载后事件数量变化 | 在稳定 GRE 捕获接口关闭并检查卸载，保存 PCAP 丢包计数 |
| 固定抓包到卫星 veth 漏过切换 | 切换会移除旧接口并创建新接口 | 在稳定 `wf-gre0` 捕获，卫星 veth 只用于路径检查 |
| 清理异常覆盖原始失败 | 旧错误路径曾因未初始化值再次抛错 | V3 的路由安装状态单独保存，操作失败触发恢复；browser collector 仍需接入该收尾合同 |
| 把仿真逻辑秒当墙钟秒 | 历史 HTTP 阶段有逻辑时间/实际时间偏差 | V3 manifest 同时保存拓扑时间与单调时钟窗口；原始 PCAP 保留窗口保护区 |
| 两列 trace 结构相同就合并训练 | 文件名交集不能证明相同网站、包单位、方向或 session | 来源类别按用户明确确认并记录 caveat；对新增样本仍查哈希、逐样本门槛和会话分组 |

## 运行顺序

所有命令先在普通 shell 做离线检查。StarryNet 实机操作须按项目约定在 `starrynet` tmux 会话和 `starrynet` conda 环境中手动启动；本实现没有自动启动采集。

```bash
python tools/satellite_wf_v3.py config-check
python tools/satellite_wf_v3.py source-audit \
  --output artifacts/reports/satellite_wf_v3_20261021/source_audit.json
python tools/satellite_wf_v3_route_nat.py plan \
  --client-container <GS26容器ID> --egress-container <GS27容器ID>
```

当前 `source-audit` 会返回 `user_attested_with_unresolved_semantics` 并以退出码 0 表示来源门禁已按用户授权解除；它仍会输出 16 条语义 caveat。数据集 manifest 必须固定这份审计结果的 SHA-256。严格模式 `passed` 仍保留给所有来源语义均有证据的情形。

来源准入已通过，固定对象网络验收也已通过；正式 V3 网站样本仍需 Browser/Tor collector 接入。已完成的验收由 `tools/satellite_wf_v3_fixed_object.py run --apply` 在 `starrynet` conda 环境和既有 `starrynet` tmux 会话中执行。它先检查 GS26/GS27 默认接口地址，然后启动隔离的 25 星加 2 地面站静态拓扑、安装临时 GRE/NAT、下载固定对象三次、审计五处抓包，最后清理并核对 Docker 基线。具体结果和每个 artifact 的哈希见上方报告与 manifest。

```bash
python tools/satellite_wf_v3_route_nat.py install \
  --client-container <GS26容器ID> --egress-container <GS27容器ID> \
  --state <本次运行目录>/route_nat_state.json --apply
python tools/satellite_wf_v3_route_nat.py verify \
  --state <本次运行目录>/route_nat_state.json
```

验收门槛包括两端卫星路由、GS26 默认与固定对象路由走 GRE、GRE 外层双向通过卫星接口、GS27 从 `B27-default` 出口、对象哈希一致、GRE 内层与出口抓包各见 3 个 GET/HTTP 200、GRE 外层可见且内核丢包为零、清理后 Docker inventory 恢复。Browser/Tor collector 启动环境仍须清除 `HTTP_PROXY`、`HTTPS_PROXY` 和 `ALL_PROXY`。本次是固定对象工程网络验收，不是网站采集或科学保真验证。

## 链路参数和时间记录

```python
from tools.satellite_wf_v3 import load_json, starrynet_link_profile
from starrynet.sn_synchronizer import StarryNet
from pathlib import Path

config = load_json("protocols/satellite_wf_v3/runtime_config.json")
profile = starrynet_link_profile(config, "engineering_baseline")
topology_config = (Path("protocols/satellite_wf_v3") /
                   config["topology"]["config_file"]).resolve()
sn = StarryNet(str(topology_config), GS, 1, [[1, 27]],
               local=True, argv=[], link_profile=profile)
```

`StarryNet` 可选参数不会改变舊调用；V3 profile 在 ISL/GSL 两端分别控制方向。其接口目前已连到 StarryNet 的初始建链、动态 GSL 建链和传播时延更新。若无 profile，旧配置继续沿用旧 qdisc 参数。

V3 采集契约要求捕获窗口以单调时钟标记；V3 Browser/Tor collector 尚未实现。它需要负责在浏览器容器中清除所有代理环境变量、保持原始 PCAP 及内核统计、按导航标记从稳定 `wf-gre0` 派生 trace，并把拓扑逻辑时间和 UTC/单调时钟配对写入 manifest。

## 样本准入

每条候选样本必须包含 target 页面身份、Tor 目标 stream、双向卫星路由、GRE/NAT 路径、稳定捕获接口、零内核抓包丢包、offload 检查、PCAP 到 trace 审计、清理状态，以及带哈希的 PCAP、trace 与样本 manifest。数据集 manifest 还必须固定已准入的 source-audit 哈希（本数据集为带 caveat 的用户确认状态），并给每条样本标注类别、来源域、独立 session group 与 train/validation/test split。

```bash
python tools/satellite_wf_v3.py admission-check \
  --source-audit artifacts/reports/satellite_wf_v3_20261021/source_audit.json \
  --manifest <候选数据集>/dataset_manifest.json \
  --output <候选数据集>/admission_audit.json
```

准入清单固定来源审计和运行配置 SHA-256，并验证类别映射哈希、目标页面最终身份、成功的 Tor stream 与三跳 circuit、实际卫星路径、UTC/单调时钟边界、拓扑逻辑时间、切换中断记录、原始 PCAP、派生 trace、路由事件、拓扑事件及会话隔离。运行配置副本放在 artifact root 下的 `protocol/runtime_config.json`。准入只决定候选文件是否具备训练数据准入条件；不会生成、改写、补齐或截断 trace，也不会把工程通过解释为真实 Starlink 科学保真。
