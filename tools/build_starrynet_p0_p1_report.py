#!/usr/bin/env python3
"""Build a dated, editable DOCX summary of the StarryNet P0/P1 runs."""

import argparse
import html
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

from bs4 import BeautifulSoup, NavigableString, Tag


ROOT = Path(__file__).resolve().parents[1]
DATE = "20261011"
STEM = "StarryNet_P0_P1_experiment_summary_" + DATE


def esc(value):
    return html.escape(str(value), quote=True)


def table(headers, rows):
    head = "".join("<th>{}</th>".format(esc(item)) for item in headers)
    body = []
    for row in rows:
        cells = []
        for cell in row:
            if isinstance(cell, SafeHtml):
                cells.append(str(cell))
            else:
                cells.append("<td>{}</td>".format(esc(cell)))
        body.append("<tr>{}</tr>".format("".join(cells)))
    return "<table><thead><tr>{}</tr></thead><tbody>{}</tbody></table>".format(head, "".join(body))


class SafeHtml(str):
    pass


def report_html():
    overview = table(
        ["阶段", "目标", "结果", "结论"],
        [
            ["P0 原生网络", "建立 25 星 + 2 地面站动态拓扑，验证路由、连通、TCP 和资源清理",
             "basic_smoke_passed=true；cleanup_verified=true",
             "本机工程闭环通过；参数保真未验证"],
            ["P1 固定 HTTP", "切换前后访问同一 1 MiB 对象，并在客户端和服务端留存 PCAP",
             "HTTP、大小、SHA-256、双端 PCAP 与清理检查通过",
             "应用层工程链路通过；不构成真实 Starlink 保真验证"],
        ],
    )

    chronology = table(
        ["阶段", "发现的问题", "处理和证据"],
        [
            ["运行兼容性", "宿主环境为 Python 3.6；`subprocess` 不接受 `text=True`，P0 在预检阶段退出。",
             "改为兼容旧 Python 的文本输出处理；保留 Python 3.6 和 3.12 的入口/测试验证。"],
            ["P0 首次全网运行", "GS27 接入新卫星链路时，已有 BIRD 导出的 `9.2.7.0/24` 路由与新接口地址冲突，Docker 拒绝配置接口。",
             "两节点回归复现后，只暂停两端原本启用的 BIRD kernel 导出，清理目标冲突路由，完成链路接入后恢复原状态。回归 ping 2/2，清理通过。"],
            ["P0 完整复跑", "切换期间采样到路由暂不可达；其余稳定时段恢复连通。",
             "完整运行通过：25 星 + 2 GS、一次 GS27 接入切换；所有预期输出存在，TCP 吞吐为正，结束资源回到基线。"],
            ["P1 首次运行", "实际对象传输完成，但 curl 指标格式解析错误，且客户端 HTTP 字段解码计数不足，导致自动验收失败。",
             "修正指标格式处理；同时保留 tshark 解码计数，并以 PCAP 原始响应头、下载大小和哈希交叉验证。"],
            ["P1 成功复跑", "没有新的运行阻断。",
             "切换前后对象下载、双端抓包、哈希校验和清理均通过；将自动解码计数的差异记入报告。"],
        ],
    )

    p0 = table(
        ["观测项", "实测结果"],
        [
            ["拓扑", "25 颗卫星、2 个地面站；100 份 27×27 时延矩阵；GS27 在仿真调度第 53 秒从卫星 13 切换到卫星 7。"],
            ["切换前连通", "第 15/25/35/45 秒平均 RTT 为 199.780/199.616/199.308/198.809 ms；各次仅发送 4 个 ping，分别收到 3/3/2/4 个。"],
            ["切换窗口", "第 55 秒采样时路由不可达；第 65 秒恢复为 4/4，平均 RTT 22.807 ms。10 秒采样间隔只能说明 65 秒采样已恢复，不能测出精确中断时长。"],
            ["恢复后连通", "第 65/75/85/95 秒平均 RTT 为 22.807/21.805/20.597/19.997 ms。"],
            ["TCP 接收吞吐", "第 35 秒 2.21 Mbit/s；第 75 秒 5.78 Mbit/s。它们是本次受限仿真的单次测量，不是链路容量基准。"],
            ["资源清理与耗时", "结束后容器、服务、网络 inventory 与启动前一致；墙钟运行时间 315.24 秒。"],
            ["最终状态", "`basic_smoke_passed=true`、`cleanup_verified=true`；`scientific_fidelity_verified=false`、`bandwidth_limit_verified=false`、`loss_rate_verified=false`、`handover_verified=false`。拓扑记录确实观察到一次切换，但摘要的正式 handover 验证标志仍为 false。"],
        ],
    )

    p1 = table(
        ["观测项", "切换前（仿真秒 35）", "切换后（仿真秒 75）"],
        [
            ["接入路径", "GS27 经卫星 13（B27-eth13）", "GS27 经卫星 7（B27-eth7）"],
            ["HTTP 与数据", "HTTP 200；1,048,576 B", "HTTP 200；1,048,576 B"],
            ["curl 总耗时", "10.939 s", "0.181 s"],
            ["对象 SHA-256", "c8411639cfd76fea51e53e9fdbc6c8cc13224e48aee23b20312040c10072aeef", "与切换前完全一致"],
            ["GS26→GS27 ping", "4/4；平均 RTT 199.127 ms", "4/4；平均 RTT 21.764 ms"],
            ["客户端 PCAP", SafeHtml("<td colspan='2'>939 包 / 2,178,744 B；2 个 GET；原始负载中有 2 个 `HTTP/1.0 200 OK` 响应头。</td>")],
            ["服务端 PCAP", SafeHtml("<td colspan='2'>938 包 / 2,214,804 B；2 个 GET；原始负载中有 2 个 `HTTP/1.0 200 OK` 响应头。</td>")],
            ["HTTP 字段解码", SafeHtml("<td colspan='2'>tshark 在每份 PCAP 中各识别 1 个结构化 HTTP 200 响应；另一响应头存在于原始 TCP 负载中。以上抓包计数覆盖整次运行两次访问。</td>")],
            ["最终状态", SafeHtml("<td colspan='2'>engineering_http_capture_passed=true；payload_integrity_passed=true；dual_endpoint_http_pcap_passed=true；cleanup_verified=true；scientific_fidelity_verified=false。</td>")],
        ],
    )

    limits = table(
        ["已有证据支持", "目前不能据此声称"],
        [
            ["本机 StarryNet 动态拓扑、OSPF/卫星路由、端到端 ping/TCP、HTTP 对象传输、双端抓包和限定范围清理能够形成可复现工程闭环。",
             "当前演示配置等同真实 Starlink 参数、已经测得 Starlink 的带宽/丢包分布、实现无缝切换或达到某个中断时限。"],
            ["一次切换前后 HTTP 访问均完成，且下载内容逐字节校验一致。",
             "10.939 秒与 0.181 秒的差异由切换单独造成，或可据此估算链路容量。每个阶段只有一个样本；随机 1% 演示丢包、TCP 重传及路径变化都可能影响耗时。"],
            ["每份 PCAP 中都能找到 2 个原始 200 响应头；应用层下载大小与 SHA-256 均匹配。",
             "tshark 的结构化 HTTP 响应计数完整覆盖全部响应；自动解码各只识别 1 个，报告如实保留了该差异。"],
        ],
    )

    artifacts = table(
        ["证据", "路径"],
        [
            ["P0 最终运行摘要", "artifacts/p0/20261010T105142_634407Z/summary.json"],
            ["P0 冻结配置、命令日志、路由、ping、iperf 与快照", "artifacts/p0/20261010T105142_634407Z/"],
            ["BIRD 路由冲突双节点回归", "artifacts/p0/route_conflict_regression_20261010/report.json"],
            ["P1 最终运行摘要与原始 PCAP", "artifacts/p1_http/20261010T114142_567556Z/"],
            ["P1 首次运行（保留的验收失败记录）", "artifacts/p1_http/20261010T113417_310960Z/summary.json"],
            ["阶段说明与复现步骤", "P0_SMOKE.md；P1_HTTP_SMOKE.md"],
        ],
    )

    sections = [
        """<h1>StarryNet P0 / P1 实验过程与结果总结</h1>
<p class="subtitle">本机动态卫星网络、HTTP 传输与双端抓包验证</p>
<p class="meta">报告日期：2026 年 10 月 11 日　｜　实验运行：2026 年 10 月 10 日（运行目录使用 UTC 时间戳）</p>
<div class="callout"><strong>结论：</strong> P0 原生网络与 P1 固定 HTTP/双端 PCAP 的工程验收均通过，实验资源完成清理。当前证据验证的是本机仿真链路可运行、可观测、可复现；Starlink 参数保真和真实卫星链路结论尚未建立。</div>
<h2>结论概览</h2>""" + overview,
        "<h2>实验目标与配置</h2><p>P0 先验证 StarryNet 能否建立动态拓扑、运行 OSPF、形成卫星接口路由，并让 GS26 经卫星网络访问 GS27。P1 在同一类拓扑上增加固定 HTTP 对象访问，在切换前后各发起一次下载，同时在客户端和服务端网络命名空间抓包。</p><p>本次拓扑为 5 个轨道面、每轨 5 颗卫星及 2 个地面站，共 27 个节点；仿真时长 100 秒，记录 100 份 27×27 时延矩阵。演示配置中的 5 Gbit/s 和 1% 丢包并非来自 Starlink 实测校准。宿主 Python 环境为 3.6.15；P0、P1 最终运行墙钟时间分别为 315.24 秒和 318.69 秒。</p><p>P0 入口的 15 项针对性测试覆盖配置、资源清理范围、链路参数更新、切换验收与异常传播。本次再次在 Python 3.12 下运行，15 项全部通过；项目阶段记录中 Python 3.6 环境下也通过。</p><h2>过程与问题修复</h2>" + chronology,
        "<h2>P0：原生网络验证结果</h2><p>最终完整运行目录：<code>artifacts/p0/20261010T105142_634407Z/</code>。GS27 在仿真调度第 53 秒从卫星 13 切换到卫星 7。稳定时段路由经卫星接口，TCP/iperf 两次接收吞吐均大于零，且实验结束后的容器、服务和网络 inventory 与启动前一致。</p>" + p0,
        "<h2>P1：HTTP 与双端抓包结果</h2><p>最终成功运行目录：<code>artifacts/p1_http/20261010T114142_567556Z/</code>。固定对象在调度第 35 秒和第 75 秒下载，拓扑切换记录在第 53 秒。两次下载都返回 HTTP 200、大小一致、SHA-256 与源文件相同。</p>" + p1,
        "<h2>结果解释与证据边界</h2>" + limits + "<p>仿真调度秒不是精确物理墙钟：P1 两次访问的触发时间分别约在仿真启动后 36.932 秒和 85.142 秒。ping 的采样间隔为 10 秒；第 55 秒不可达、第 65 秒恢复的记录不能提供更细的切换中断时长。</p><h2>建议的下一阶段</h2><p>进入 P2 前先检查现有 StarryNet 节点镜像是否包含可用 Tor 程序；随后只跑一个受控 Tor 电路和一个固定静态网页访问，在客户端与出口/服务端同时抓包，核验电路建立、页面内容完整性、流量路径与清理状态。该单次闭环通过后，再考虑批量网页访问。真实 Starlink 参数校准应另行使用测量数据，不能由本次示例值推断。</p><h2>可追溯运行证据</h2>" + artifacts,
    ]

    style = """
    <style>
      @page { size: A4; margin: 17mm 16mm 17mm 16mm; }
      body { font-family: 'Noto Sans CJK SC', 'Microsoft YaHei', sans-serif; font-size: 9.5pt; color: #233044; line-height: 1.42; }
      h1 { color: #12345a; font-size: 25pt; margin: 20mm 0 2mm; }
      h2 { color: #12345a; font-size: 15pt; margin: 7mm 0 3mm; border-bottom: 1px solid #b6c6d8; padding-bottom: 2mm; }
      p { margin: 2mm 0 3mm; }
      .subtitle { font-size: 14pt; color: #52718f; margin: 0 0 6mm; }
      .meta { color: #526173; font-size: 9pt; margin-bottom: 7mm; }
      .callout { background: #eaf2f9; border-left: 4px solid #2c6a9f; padding: 4mm; margin: 5mm 0; }
      table { width: 100%; border-collapse: collapse; margin: 3mm 0 5mm; font-size: 8.6pt; }
      th { background: #dce8f3; color: #183b5b; text-align: left; }
      th, td { border: 1px solid #b9c6d2; padding: 2.2mm; vertical-align: top; }
      tr { page-break-inside: avoid; }
      code { font-family: 'Liberation Mono', monospace; font-size: 8pt; color: #314b65; }
    </style>
    """
    return "<!DOCTYPE html><html><head><meta charset='utf-8'><title>StarryNet P0/P1 实验总结</title>{}</head><body>{}</body></html>".format(style, "".join(sections))


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
ET.register_namespace("w", W)
ET.register_namespace("r", R)


def qn(local):
    return "{{{}}}{}".format(W, local)


def word_run(parent, text, bold=False, code=False):
    run = ET.SubElement(parent, qn("r"))
    props = ET.SubElement(run, qn("rPr"))
    fonts = ET.SubElement(props, qn("rFonts"))
    fonts.set(qn("ascii"), "Consolas" if code else "Noto Sans CJK SC")
    fonts.set(qn("hAnsi"), "Consolas" if code else "Noto Sans CJK SC")
    fonts.set(qn("eastAsia"), "Noto Sans CJK SC")
    if bold:
        ET.SubElement(props, qn("b"))
    if code:
        ET.SubElement(props, qn("color"), {qn("val"): "314B65"})
    node = ET.SubElement(run, qn("t"))
    if text[:1].isspace() or text[-1:].isspace():
        node.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
    node.text = text


def add_inline(parent, node, bold=False, code=False):
    if isinstance(node, NavigableString):
        if str(node):
            word_run(parent, str(node), bold=bold, code=code)
        return
    if not isinstance(node, Tag):
        return
    new_bold = bold or node.name in ("strong", "b")
    new_code = code or node.name == "code"
    for child in node.children:
        add_inline(parent, child, new_bold, new_code)


def add_paragraph(parent, source, style=None):
    p = ET.SubElement(parent, qn("p"))
    ppr = ET.SubElement(p, qn("pPr"))
    if style:
        ET.SubElement(ppr, qn("pStyle"), {qn("val"): style})
    for child in source.children:
        add_inline(p, child)
    return p


def add_table(parent, source):
    tbl = ET.SubElement(parent, qn("tbl"))
    props = ET.SubElement(tbl, qn("tblPr"))
    ET.SubElement(props, qn("tblW"), {qn("w"): "10000", qn("type"): "dxa"})
    ET.SubElement(props, qn("tblLayout"), {qn("type"): "autofit"})
    borders = ET.SubElement(props, qn("tblBorders"))
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        ET.SubElement(borders, qn(edge), {
            qn("val"): "single", qn("sz"): "4", qn("space"): "0", qn("color"): "B9C6D2"
        })
    margins = ET.SubElement(props, qn("tblCellMar"))
    for edge, value in (("top", "90"), ("left", "100"), ("bottom", "90"), ("right", "100")):
        ET.SubElement(margins, qn(edge), {qn("w"): value, qn("type"): "dxa"})
    source_rows = source.find_all("tr")
    column_count = max(sum(int(c.get("colspan", "1")) for c in row.find_all(["th", "td"], recursive=False)) for row in source_rows)
    grid = ET.SubElement(tbl, qn("tblGrid"))
    col_width, remainder = divmod(10000, column_count)
    for column_index in range(column_count):
        ET.SubElement(grid, qn("gridCol"), {qn("w"): str(col_width + (1 if column_index < remainder else 0))})
    for row_index, source_row in enumerate(source_rows):
        row = ET.SubElement(tbl, qn("tr"))
        ET.SubElement(ET.SubElement(row, qn("trPr")), qn("cantSplit"))
        for source_cell in source_row.find_all(["th", "td"], recursive=False):
            cell = ET.SubElement(row, qn("tc"))
            tcpr = ET.SubElement(cell, qn("tcPr"))
            span = int(source_cell.get("colspan", "1"))
            if span > 1:
                ET.SubElement(tcpr, qn("gridSpan"), {qn("val"): str(span)})
            if row_index == 0:
                ET.SubElement(tcpr, qn("shd"), {qn("fill"): "DCE8F3"})
            paragraph = ET.SubElement(cell, qn("p"))
            ppr = ET.SubElement(paragraph, qn("pPr"))
            ET.SubElement(ppr, qn("spacing"), {qn("after"): "35"})
            for child in source_cell.children:
                add_inline(paragraph, child, bold=(row_index == 0))
            if len(paragraph) == 1:
                word_run(paragraph, "", bold=(row_index == 0))
    return tbl


def build_docx_from_html(html_path, docx_path):
    soup = BeautifulSoup(html_path.read_text(encoding="utf-8"), "html.parser")
    document = ET.Element(qn("document"))
    body = ET.SubElement(document, qn("body"))
    for item in soup.body.children:
        if not isinstance(item, Tag):
            continue
        if item.name == "h1":
            add_paragraph(body, item, "Title")
        elif item.name == "h2":
            add_paragraph(body, item, "Heading1")
        elif item.name == "table":
            add_table(body, item)
        elif item.name == "div" and "callout" in item.get("class", []):
            p = ET.SubElement(body, qn("p"))
            ppr = ET.SubElement(p, qn("pPr"))
            ET.SubElement(ppr, qn("shd"), {qn("fill"): "EAF2F9"})
            for child in item.children:
                add_inline(p, child)
        elif item.name == "p":
            style = "Subtitle" if "subtitle" in item.get("class", []) else None
            if "meta" in item.get("class", []):
                style = "Caption"
            add_paragraph(body, item, style)
    sect = ET.SubElement(body, qn("sectPr"))
    ET.SubElement(sect, qn("pgSz"), {qn("w"): "11906", qn("h"): "16838"})
    ET.SubElement(sect, qn("pgMar"), {
        qn("top"): "850", qn("right"): "900", qn("bottom"): "850", qn("left"): "900",
        qn("header"): "400", qn("footer"): "400", qn("gutter"): "0"
    })

    styles = ET.Element(qn("styles"))
    normal = ET.SubElement(styles, qn("style"), {qn("type"): "paragraph", qn("default"): "1"})
    ET.SubElement(normal, qn("name"), {qn("val"): "Normal"})
    normal_ppr = ET.SubElement(normal, qn("pPr"))
    ET.SubElement(normal_ppr, qn("spacing"), {qn("after"): "100", qn("line"): "276", qn("lineRule"): "auto"})
    normal_rpr = ET.SubElement(normal, qn("rPr"))
    normal_fonts = ET.SubElement(normal_rpr, qn("rFonts"))
    for attr in ("ascii", "hAnsi", "eastAsia"):
        normal_fonts.set(qn(attr), "Noto Sans CJK SC")
    ET.SubElement(normal_rpr, qn("sz"), {qn("val"): "19"})
    for style_id, name, size, color in (
        ("Title", "Title", "40", "12345A"),
        ("Subtitle", "Subtitle", "26", "52718F"),
        ("Heading1", "heading 1", "29", "12345A"),
        ("Caption", "Caption", "18", "526173"),
    ):
        style = ET.SubElement(styles, qn("style"), {qn("type"): "paragraph", qn("styleId"): style_id})
        ET.SubElement(style, qn("name"), {qn("val"): name})
        if style_id == "Heading1":
            ET.SubElement(style, qn("basedOn"), {qn("val"): "Normal"})
        ppr = ET.SubElement(style, qn("pPr"))
        if style_id == "Heading1":
            ET.SubElement(ppr, qn("keepNext"))
        rpr = ET.SubElement(style, qn("rPr"))
        fonts = ET.SubElement(rpr, qn("rFonts"))
        for attr in ("ascii", "hAnsi", "eastAsia"):
            fonts.set(qn(attr), "Noto Sans CJK SC")
        ET.SubElement(rpr, qn("b"))
        ET.SubElement(rpr, qn("color"), {qn("val"): color})
        ET.SubElement(rpr, qn("sz"), {qn("val"): size})

    content_types = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>
</Types>"""
    root_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
</Relationships>"""
    doc_rels = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
</Relationships>"""
    core = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/">
<dc:title>StarryNet P0/P1 实验过程与结果总结</dc:title><dc:subject>本机动态卫星网络、HTTP 与双端抓包工程验证</dc:subject><dc:language>zh-CN</dc:language>
</cp:coreProperties>"""
    with zipfile.ZipFile(str(docx_path), "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("word/document.xml", ET.tostring(document, encoding="utf-8", xml_declaration=True))
        archive.writestr("word/styles.xml", ET.tostring(styles, encoding="utf-8", xml_declaration=True))
        archive.writestr("word/_rels/document.xml.rels", doc_rels)
        archive.writestr("docProps/core.xml", core)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(ROOT / "artifacts" / "reports" / DATE))
    args = parser.parse_args()
    out_dir = Path(args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / (STEM + ".html")
    docx_path = out_dir / (STEM + ".docx")
    html_path.write_text(report_html(), encoding="utf-8")
    build_docx_from_html(html_path, docx_path)
    if not docx_path.is_file() or docx_path.stat().st_size == 0:
        raise RuntimeError("LibreOffice did not create the expected DOCX: {}".format(docx_path))
    print("DOCX={}".format(docx_path))
    print("HTML={}".format(html_path))
    print("DOCX_BYTES={}".format(docx_path.stat().st_size))


if __name__ == "__main__":
    main()
