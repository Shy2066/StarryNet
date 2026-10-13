# StarryNet 最小网络冒烟实验

目标是验证本机 StarryNet 能建立动态网络、运行 OSPF，并让 GS26 → 卫星网络 → GS27 的 ping 和 TCP/iperf3 流量连通。采用官方 5×5 卫星、两个地面站及默认轨道和链路参数；不注入故障、不覆盖静态下一跳。默认 5 Gbit/s 和 1% loss 是示例参数，尚未经过 Starlink 实测校准。

## 执行

在仓库目录使用已有依赖的 Python：

```bash
cd /home/shy/Project/StarryNet
python tools/p0_smoke.py plan
python tools/p0_smoke.py preflight
python tools/p0_smoke.py topology
python -u tools/p0_smoke.py run
```

`plan` 只显示安排；`preflight` 只读检查 Docker；`topology` 生成 100 个 27×27 时延矩阵及 OSPF 配置，不创建容器；`run` 才启动网络。普通账号需要能访问 Docker daemon。脚本不安装软件、不初始化 Swarm、不读取远程示例账号。

本机入口支持 Linux/Python 3.6+；最近的完整网络运行和 P1 HTTP 运行均在 `starrynet` 环境（Python 3.6.15）完成，入口计划也在 Python 3.12.7 中解析通过。需要 numpy、skyfield、sgp4、paramiko、requests，以及本地 `lwsen/starlab_node:1.0` 镜像和单节点 Swarm manager。依赖已在本次环境检查中发现；不要直接执行会修改全局环境的 `install.sh`。如希望隔离 Python 包写入，可以使用 `python -m venv --system-site-packages .venv`，再将上述命令中的 `python` 换为 `.venv/bin/python`；它复用当前 Python 已安装的依赖。

预计运行需要约 4–8 分钟，视 Docker 节点准备和链路创建速度而定；包含上游固定 120 秒 OSPF 等待和 100 秒仿真。首次 Docker 准备可能更慢。服务创建异步返回，节点等待限制为 90 秒；单条本机执行命令限制为 600 秒。

## 输出和判定

每次生成独立的 `artifacts/p0/<UTC时间>/`，不会覆盖旧 `starlink-5-5-550-53-grid-LeastDelay/`。

- `config.json`：本次配置，远程账号字段为空。
- `manifest.json`：源码 commit、运行时源码 SHA-256、Python 版本和测量时间点。
- `source/`：本次源码副本，动态更新始终从该副本上传，避免运行中修改仓库影响实验。
- `topology.json`：矩阵结构、接入缺失秒数、地面站切换次数和时延变化次数。
- `commands.log`：本机执行命令及 stdout/stderr。
- `snapshot_before.json`、`snapshot_after.json`：节点接口、路由、qdisc、BIRD 状态和 GS26 → GS27 路由。
- `p0-5-5-550-53-grid-LeastDelay/`：时延、位置、切换、BIRD 配置，以及 9 份 ping、2 份 iperf 和 6 份路由输出。
- `summary.json`：成功与失败状态。出现异常也会尽力写入摘要并清理。

`basic_smoke_passed=true` 要求所有计划输出存在，稳定时段的 ping 至少收到一个响应，iperf 两次接收吞吐均为正，目的路由使用卫星接口，且结束后的容器、服务、网络 inventory 与启动前一致。真实拓扑切换后 10 秒内的采样允许记录丢包或暂时路由不可达，原始结果和摘要必须保留；窗口外的计划采样仍必须收到响应。这是观测采样的容许窗口，不能证明中断时长不超过 10 秒。ping 的失败返回码被记录为测量结果，其他命令失败仍会终止验收。

10 秒是本入口暂定的采样验收门槛，不是 StarryNet 官方指标。基本闭环通过不会自动认定带宽上限、统计丢包率、无缝切换或科学保真度已经验证。`summary.json` 为这些项目保留单独的 false 状态。

所有节点的 Docker 管理接口在创建链路后关闭，只保留 `lo` 和 StarryNet `B*` 接口，防止地面站通过管理网络通信。本机命令失败及 Python worker 异常会终止验收。

## 资源范围

启动前拒绝已有 `constellation-test` 服务、`ovs_container_*` 容器、StarryNet 链路名称或冲突子网；`.p0.lock` 防止重复启动本机 P0。容器通过 `com.docker.swarm.service.name=constellation-test` 筛选并按节点编号排序；新网络带有 `starrynet.owner=constellation-test` 标签。

清理只针对这些资源。旧版未带标签的网络会保留，需要人工确认归属后处理。强制杀进程或宿主机异常可能使 finally 来不及执行，确认没有实验仍在运行后可使用：

```bash
python -m starrynet.clean
```

## 代码验证

```bash
python tools/test_p0_smoke.py
git diff --check
```

15 项测试覆盖配置路径、服务过滤和数字编号、清理范围、文件复制边界、命令错误传播、时延更新保留速率/丢包、切换时每端只创建一个完整 qdisc，切换窗口与其他时段的断连判定，以及跨版本工作线程异常传播和独立上传脚本导入。

P1 固定 HTTP 对象和双端 PCAP 阶段已经完成，配置和实跑结果见 [P1_HTTP_SMOKE.md](P1_HTTP_SMOKE.md)。后续再接入 Tor 工作负载；Starlink 参数校准仍需要测量数据，不能由当前示例配置推得。

## 2026-10-10 实跑结果

最新完整运行：[20261010T105142_634407Z](artifacts/p0/20261010T105142_634407Z/summary.json)。本次墙钟 315.24 秒，使用该目录内冻结源码，源文件哈希核对通过。9 份 ping、2 份 iperf、6 份路由输出及前后快照均保留。

| 项目 | 结果 |
| --- | --- |
| 节点、链路和 OSPF | 25 颗卫星 + 2 个地面站成功创建，OSPF 生成卫星接口路由 |
| 切换前 RTT | 第 15/25/35/45 秒平均 RTT 为 198.809–199.780 ms |
| 第 53 秒切换 | GS27 从卫星 13 切换到卫星 7；第 55 秒采样不可达，第 65 秒恢复为 4/4 收到响应 |
| 恢复后的 RTT | 第 65/75/85/95 秒平均 RTT 为 19.997–22.807 ms |
| TCP 接收吞吐 | 第 35 秒 2.21 Mbit/s；第 75 秒 5.78 Mbit/s |
| 结束清理 | 通过；容器、服务和网络 inventory 与开始前一致 |
| 完整验收 | `basic_smoke_passed=true`；55 秒采样处于预设切换窗口内 |

这里的秒数是仿真调度编号，不是精确墙钟时间；10 秒间隔的 ping 无法给出精确中断时长。早期失败尝试的错误、日志和清理结果也保留在各自运行目录。

已修复配置路径被忽略、全局 Docker 清理、容器编号不稳定、链路设置异步竞争、旧 iproute2 输出兼容、切换重复添加根 qdisc、时延更新丢失速率/丢包设置及动态接入路由冲突等问题；15 项针对性测试已在 Python 3.6 和 3.12 中通过。P0 的暂定切换采样门槛通过，P1 的固定 HTTP 对象在切换前后均完成且两端抓包保留。当前证据证明本地仿真工程闭环可运行，不等同于 Starlink 物理参数保真。


## 动态接入路由冲突修复

用户运行 `20261010T091922_633675Z` 在 GS27 接入新链路时失败：内核已有 BIRD 导出的 `9.2.7.0/24 via 9.2.13.50`，Docker 拒绝安装新接口地址 `9.2.7.60/24`。该次失败后的清理检查通过。

动态接入现在先暂停两个端点上原本启用的 BIRD kernel 协议，仅对待接入网段删除残留的 `proto bird` 路由，再创建及配置两个接口，最后恢复原本启用的 kernel 协议。OSPF 协议继续运行；接入失败时也会尝试恢复导出，原本禁用的 kernel 协议不会被启用。这个阶段会暂时影响端点的 BIRD 内核路由，不承诺缩短 OSPF 收敛时间。

[两节点 Docker 回归报告](artifacts/p0/route_conflict_regression_20261010/report.json)使用用户的 Python 3.6.15 和已有镜像，实际复现了相同路由冲突；修复后的接口接入成功，kernel 导出恢复，ping 2 发 2 收，容器和网络清理验证通过。当前 15 项测试在 Python 3.6 和 3.12 中通过，新增覆盖双端暂停顺序、失败恢复及原禁用状态保留。完整 27 节点动态实验需要用户重新执行；之前的切换恢复门槛仍保留。
