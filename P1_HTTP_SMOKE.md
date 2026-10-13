# StarryNet P1 固定 HTTP 与双端抓包

P1 在 P0 的 25 星 + 2 地面站动态拓扑上，把一份固定的 1 MiB 对象从 GS26 下载到 GS27。程序根据本次拓扑生成的第一个地面站切换时刻，分别在切换前和切换后发起一次 HTTP/1.1 请求；同时在两个端点的网络命名空间抓取 TCP 端口 18080，并核对对象大小、HTTP 状态码和 SHA-256。

## 复现

```bash
cd /home/shy/Project/StarryNet
python -u tools/p1_http_smoke.py plan
python -u tools/p1_http_smoke.py preflight
python -u tools/p1_http_smoke.py run
```

运行依赖与 P0 相同，主机还需安装 `tshark` 以读取 PCAP。完整运行约 5 分钟，包含 StarryNet 原生的 120 秒路由等待和 100 秒仿真。P1 和 P0 共用 `.p0.lock`，避免同时争用固定 Docker 服务名。

每次运行写入独立的 `artifacts/p1_http/<UTC时间>/`。`manifest.json` 记录对象哈希、拓扑源码哈希、客户端/服务端抓包过滤器和 tshark 版本；`source/` 保存当次运行的源码；`downloads/` 保存源对象对应的两份下载副本及 curl 指标；`captures/` 保存原始 PCAP 和提取的 HTTP 包摘要；`snapshot_before.json`、`snapshot_after.json` 与 `summary.json` 保存路由和验收状态。

## 运行结果

成功运行目录为 [`20261010T114142_567556Z`](artifacts/p1_http/20261010T114142_567556Z/summary.json)，总墙钟时间 318.69 秒。源码哈希与 manifest 一致；容器、服务和带标签网络均已清理，`cleanup_verified=true`。

| 观测项 | 切换前 | 切换后 |
| --- | ---: | ---: |
| 仿真调度秒 | 35 | 75 |
| GS27 接入卫星 | 13 | 7 |
| curl 完成时间 | 10.939 s | 0.181 s |
| HTTP 状态 / 下载大小 | 200 / 1,048,576 B | 200 / 1,048,576 B |
| 下载对象 SHA-256 | `c8411639cfd76fea51e53e9fdbc6c8cc13224e48aee23b20312040c10072aeef` | 相同 |
| GS26 → GS27 ping | 4/4，199.127 ms | 4/4，21.764 ms |

拓扑记录的切换发生在仿真第 53 秒。切换前 GS27 到 GS26 的路由经 `9.2.13.50`、接口 `B27-eth13`；切换后经 `9.2.7.50`、接口 `B27-eth7`。第 55 秒 ping 记录“网络不可达”，第 75 秒恢复；P0 的上一轮完整采样在第 65 秒已恢复。两次 HTTP 对象下载都跨过完整应用层校验。

客户端 PCAP 为 2,178,744 B、939 个包；服务端 PCAP 为 2,214,804 B、938 个包。每份均包含 2 个 `GET /fixed-object.bin` 和 2 个原始 TCP 负载中的 `HTTP/1.0 200 OK` 响应头。tshark 的 HTTP 字段解码各识别出 1 个 200 响应；另一个响应头在 PCAP 原始负载中存在，但未被该解码字段标注。两端抓包均保留了完整对象传输量，客户端两次下载的哈希也匹配，因此入口按原始响应头和应用层对象校验通过，并在摘要中同时保留 dissector 计数。

入口记录的 HTTP 触发 wall-clock 时间分别为仿真启动后 36.932 秒和 85.142 秒。StarryNet 的这些 `35`、`75` 秒值是调度编号；拓扑更新会造成仿真逻辑秒和墙钟时间有偏差，不能把调度编号当成严格物理时钟。

## 证据边界

这是两次固定对象访问，每个网络阶段只有一个样本。10.939 秒与 0.181 秒的差异和 ping RTT 变化方向一致，但随机 1% 链路丢包、TCP 重传及路径切换都会影响时长；这组结果不能单独归因，也不能用来估算 5 Gbit/s 的可用链路容量。配置中的 5 Gbit/s 和 1% 丢包仍是演示值，尚未用真实 Starlink 联合链路测量校准。

这一步建立了应用层 TCP/HTTP 与 PCAP 的工程闭环，没有运行 Tor 浏览流量，也没有验证真实网页指纹分布、轨道参数保真或 Starlink 端到端物理保真。P1 首次执行目录 [`20261010T113417_310960Z`](artifacts/p1_http/20261010T113417_310960Z/summary.json) 也保留：传输本身和服务端 PCAP 已成功，但当时 curl 指标格式和客户端响应解码验收写法有误；修复后完整重跑得到上面的通过结果。
