# -*- coding: utf-8 -*-
# 设计说明：PDF 报告生成
# 为什么：一次测试的结论得有一份能拿走的交付物。页面上看是一回事，给别人看、留档、
#         当毕设材料都得是文件
# 放弃了：不做在线预览。V1.0 直接生成 PDF 让浏览器下载，省掉一整套预览渲染
#
# 2026-10-02 中文字体是这一步最大的坑。reportlab 默认的 Helvetica 不带中文字形，
# 不换字体的话整份报告的中文全是空白方块，而且它不报错、不警告，只有打开 PDF 才看得出来
import json
import logging
from datetime import datetime
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.cidfonts import UnicodeCIDFont
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from config import APP_NAME, APP_VERSION, REPORT_DIR
from models.database import SessionLocal
from models.tables import AuditLog, Finding, Job, Target

logger = logging.getLogger("ai_scanner.report")

# 系统自带的黑体。选它是因为 ttf 单文件、字形清楚，不用处理 ttc 的子字体索引
WINDOWS_FONT_PATH = "C:/Windows/Fonts/simhei.ttf"
# 系统字体找不到时退到 reportlab 自带的 CID 字体，它不需要任何外部字体文件
FALLBACK_CID_FONT = "STSong-Light"
REGISTERED_FONT_NAME = "AiScannerCJK"

# 风险等级的中文说法
LEVEL_LABELS = {"high": "高", "medium": "中", "low": "低"}

# 报告里单条证据留多长。留太长一页放不下，留太短又看不出问题
EVIDENCE_LIMIT = 500
# 附录里列多少条审计日志
AUDIT_LIMIT = 40


def report_register_cjk_font():
    # 设计说明：注册一个能渲染中文的字体，返回字体名
    # 为什么：这一步必须先做。用默认字体生成出来的 PDF 里中文全是空白方块，
    #         而且不抛异常，等发现时报告已经发出去了
    # 放弃了：不把字体文件打进仓库。几 MB 的字体进 git 纯属浪费，用系统自带的就行
    font_path = Path(WINDOWS_FONT_PATH)
    if font_path.exists():
        try:
            pdfmetrics.registerFont(TTFont(REGISTERED_FONT_NAME, str(font_path)))
            return REGISTERED_FONT_NAME
        except Exception as font_error:
            logger.warning("系统字体 %s 注册失败，改用自带中文字体：%s", font_path, font_error)

    try:
        pdfmetrics.registerFont(UnicodeCIDFont(FALLBACK_CID_FONT))
        return FALLBACK_CID_FONT
    except Exception as fallback_error:
        # 连自带字体都注册不上，只能退回默认字体。这时中文会缺字，日志里必须留痕
        logger.error("连 reportlab 自带的中文字体都注册不上，报告中文会缺字：%s", fallback_error)
        return "Helvetica"


def report_build_styles(font_name):
    # 设计说明：报告用到的几种段落样式集中定义
    # 为什么：字号行距散在各处写，改一次要翻遍全文件；集中一处顺手就能统一调版式
    base_styles = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "ReportTitle", parent=base_styles["Title"],
            fontName=font_name, fontSize=22, leading=32),
        "subtitle": ParagraphStyle(
            "ReportSubtitle", parent=base_styles["Normal"],
            fontName=font_name, fontSize=11, leading=19, textColor=colors.HexColor("#555555")),
        "heading": ParagraphStyle(
            "ReportHeading", parent=base_styles["Heading1"],
            fontName=font_name, fontSize=14, leading=22, spaceBefore=16, spaceAfter=8),
        "body": ParagraphStyle(
            "ReportBody", parent=base_styles["Normal"],
            fontName=font_name, fontSize=10, leading=17),
        "note": ParagraphStyle(
            "ReportNote", parent=base_styles["Normal"],
            fontName=font_name, fontSize=8.5, leading=14, textColor=colors.HexColor("#666666")),
    }


def report_parse_safe_text(raw_text):
    # 设计说明：把要放进 Paragraph 的文本转义
    # 为什么：Paragraph 认的是 XML 标记，而报告里的证据全是 HTTP 响应片段，尖括号遍地都是，
    #         不转义的话一个 <input> 就能让整份报告生成失败
    return (
        str(raw_text if raw_text is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def report_parse_level_label(level_value):
    # 设计说明：把风险等级翻成中文
    # 为什么：报告是给人看的，"high" 这种词不适合直接印上去
    return LEVEL_LABELS.get(str(level_value or "").lower(), "未定级")


def report_build_finding_statistics(finding_items):
    # 设计说明：统计各等级的漏洞条数
    # 为什么：执行摘要上要一眼能看出严重程度分布，这是报告里最先被看的一行
    statistics = {"high": 0, "medium": 0, "low": 0, "other": 0}
    for finding_item in finding_items:
        level_key = str(finding_item.get("vuln_level") or "").lower()
        if level_key in statistics:
            statistics[level_key] += 1
        else:
            statistics["other"] += 1
    return statistics


def report_fetch_job_data(job_id):
    # 设计说明：把生成报告要用的数据一次性取齐
    # 为什么：报告是一份快照，边生成边查库容易拿到前后不一致的数据
    # 放弃了：不做数据缓存。生成报告是低频操作，每次重新取最省心
    session = SessionLocal()
    try:
        job_row = session.query(Job).filter(Job.id == job_id).first()
        if job_row is None:
            return None

        target_row = session.query(Target).filter(Target.id == job_row.target_id).first()
        finding_rows = (
            session.query(Finding).filter(Finding.job_id == job_id).order_by(Finding.id).all()
        )
        audit_rows = (
            session.query(AuditLog).filter(AuditLog.job_id == job_id)
            .order_by(AuditLog.id.desc()).limit(AUDIT_LIMIT).all()
        )

        recon_block = {}
        if job_row.plan_snapshot:
            try:
                recon_block = json.loads(job_row.plan_snapshot).get("recon") or {}
            except ValueError:
                # 快照坏了不该让报告整个生成不出来，跳过"测试过程"那一节就行
                logger.warning("任务 %s 的计划快照解不开，报告里跳过测试过程章节", job_id)

        return {
            "job": {
                "job_id": job_row.id,
                "status": job_row.current_job_status,
                "total_round": job_row.total_round,
                "started_at": job_row.started_at.strftime("%Y-%m-%d %H:%M:%S") if job_row.started_at else "",
                "finished_at": job_row.finished_at.strftime("%Y-%m-%d %H:%M:%S") if job_row.finished_at else "",
            },
            "target": {
                "target_name": target_row.target_name if target_row else "（目标已删除）",
                "target_url": target_row.target_url if target_row else "",
                "authorized": bool(target_row.authorized_flag) if target_row else False,
                "authorized_at": target_row.authorized_at.strftime("%Y-%m-%d %H:%M") if target_row and target_row.authorized_at else "",
            },
            "findings": [
                {
                    "finding_id": finding_row.id,
                    "vuln_type": finding_row.vuln_type,
                    "vuln_level": finding_row.vuln_level,
                    "vuln_url": finding_row.vuln_url,
                    "confidence": finding_row.confidence,
                    "judge_reason": finding_row.validate_reason,
                    "evidence": finding_row.raw_evidence,
                    "fix_suggestion": finding_row.fix_suggestion,
                }
                for finding_row in finding_rows
            ],
            "audit": [
                {
                    "log_type": audit_row.log_type,
                    "log_content": audit_row.log_content,
                    "log_reason": audit_row.log_reason,
                    "created_at": audit_row.created_at.strftime("%Y-%m-%d %H:%M:%S") if audit_row.created_at else "",
                }
                for audit_row in audit_rows
            ],
            "recon": recon_block,
        }
    finally:
        session.close()


def report_build_cover_section(report_data, styles):
    # 设计说明：封面。谁扫的、扫的谁、什么时候扫的
    # 为什么：报告是要归档的东西，脱开系统单独看时，这几条信息必须自解释
    target_info = report_data["target"]
    job_info = report_data["job"]
    section = [
        Spacer(1, 40 * mm),
        Paragraph(report_parse_safe_text(APP_NAME), styles["title"]),
        Paragraph("扫描报告 %s" % APP_VERSION, styles["subtitle"]),
        Spacer(1, 24 * mm),
    ]

    cover_rows = [
        ["目标名称", target_info["target_name"]],
        ["目标地址", target_info["target_url"]],
        ["任务编号", "第 %s 号" % job_info["job_id"]],
        ["测试时间", "%s 至 %s" % (job_info["started_at"] or "—", job_info["finished_at"] or "—")],
        ["授权确认", "已于 %s 确认" % target_info["authorized_at"] if target_info["authorized"] else "未确认授权"],
        ["报告生成", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["著作权人", "[著作权人]"],
    ]
    cover_table = Table(
        [[Paragraph(report_parse_safe_text(left), styles["body"]),
          Paragraph(report_parse_safe_text(right), styles["body"])] for left, right in cover_rows],
        colWidths=[32 * mm, 110 * mm],
    )
    cover_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    section.append(cover_table)
    section.append(Spacer(1, 18 * mm))
    section.append(Paragraph(
        "本报告由系统在已获授权的测试任务中自动生成，仅供被测试方与授权方内部使用。", styles["note"]))
    section.append(PageBreak())
    return section


def report_build_summary_section(report_data, styles):
    # 设计说明：执行摘要。目标概况 + 漏洞统计 + 反思器的整场结论
    # 为什么：看报告的人多半只翻这一页，严重程度分布必须放在最前面
    recon_block = report_data["recon"]
    fingerprint_block = recon_block.get("fingerprint") or {}
    finding_items = report_data["findings"]
    statistics = report_build_finding_statistics(finding_items)
    reflection_block = recon_block.get("reflection") or {}

    section = [Paragraph("一、执行摘要", styles["heading"])]
    open_ports = [str(item.get("port")) for item in (recon_block.get("open_ports") or [])]
    section.append(Paragraph(
        "目标 %s 共开放 %s 个端口（%s）。识别到的技术栈：%s。" % (
            report_parse_safe_text(report_data["target"]["target_url"]),
            len(open_ports),
            report_parse_safe_text("、".join(open_ports) or "无"),
            report_parse_safe_text("、".join(fingerprint_block.get("technologies") or []) or "未识别"),
        ), styles["body"]))
    section.append(Spacer(1, 6))

    summary_rows = [
        ["风险等级", "数量"],
        ["高危", str(statistics["high"])],
        ["中危", str(statistics["medium"])],
        ["低危", str(statistics["low"])],
        ["合计", str(len(finding_items))],
    ]
    summary_table = Table(summary_rows, colWidths=[40 * mm, 30 * mm])
    summary_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("FONTNAME", (0, 0), (-1, -1), styles["body"].fontName),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
    ]))
    section.append(summary_table)

    if reflection_block.get("conclusion"):
        section.append(Spacer(1, 8))
        section.append(Paragraph("反思器复核结论", styles["heading"]))
        section.append(Paragraph(report_parse_safe_text(reflection_block["conclusion"]), styles["body"]))
        section.append(Paragraph(
            "本次共复核 %s 条发现，确认 %s 条，未通过 %s 条。" % (
                reflection_block.get("reviewed_count", 0),
                reflection_block.get("confirmed_count", 0),
                reflection_block.get("unconfirmed_count", 0),
            ), styles["note"]))
    return section


def report_build_finding_list_section(report_data, styles):
    # 设计说明：漏洞清单表
    # 为什么：明细太长不适合通读，先给一张能一眼扫完的清单，要细看再翻后面的详情
    section = [PageBreak(), Paragraph("二、漏洞清单", styles["heading"])]
    finding_items = report_data["findings"]
    if not finding_items:
        section.append(Paragraph("本次测试未发现漏洞。", styles["body"]))
        return section

    list_rows = [["序号", "漏洞类型", "风险等级", "置信度", "命中地址"]]
    for finding_item in finding_items:
        list_rows.append([
            str(finding_item["finding_id"]),
            str(finding_item["vuln_type"]),
            report_parse_level_label(finding_item["vuln_level"]),
            "%.2f" % (finding_item["confidence"] or 0.0),
            str(finding_item["vuln_url"] or ""),
        ])

    list_table = Table(list_rows, colWidths=[14 * mm, 32 * mm, 20 * mm, 20 * mm, 70 * mm])
    list_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("FONTNAME", (0, 0), (-1, -1), styles["body"].fontName),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTSIZE", (0, 0), (-1, 0), 9.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
        ("ALIGN", (2, 0), (3, -1), "CENTER"),
    ]))
    section.append(list_table)
    return section


def report_build_finding_detail_section(report_data, styles):
    # 设计说明：逐条漏洞详情。类型、等级、证据、修复建议
    # 为什么：清单只能看出"有几个问题"，真正要让对方能改，必须给出复现依据和修复动作
    # 放弃了：不自动生成复现命令。工具不一样、环境不一样，自动拼出来的命令多半跑不通
    section = [PageBreak(), Paragraph("三、漏洞详情", styles["heading"])]
    finding_items = report_data["findings"]
    if not finding_items:
        section.append(Paragraph("本次测试未发现漏洞，无详情可列。", styles["body"]))
        return section

    for finding_item in finding_items:
        section.append(Paragraph(
            "第 %s 条　%s（%s）" % (
                finding_item["finding_id"],
                report_parse_safe_text(finding_item["vuln_type"]),
                report_parse_level_label(finding_item["vuln_level"]),
            ), styles["heading"]))
        detail_rows = [
            ["命中地址", str(finding_item["vuln_url"] or "—")],
            ["置信度", "%.2f" % (finding_item["confidence"] or 0.0)],
            ["证据片段", str(finding_item["evidence"] or "—")[:EVIDENCE_LIMIT]],
            ["判定理由", str(finding_item["judge_reason"] or "—")[:EVIDENCE_LIMIT]],
            ["修复建议", str(finding_item["fix_suggestion"] or "—")[:EVIDENCE_LIMIT]],
        ]
        detail_table = Table(
            [[Paragraph(report_parse_safe_text(left), styles["body"]),
              Paragraph(report_parse_safe_text(right), styles["body"])] for left, right in detail_rows],
            colWidths=[24 * mm, 132 * mm],
        )
        detail_table.setStyle(TableStyle([
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dddddd")),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f5f5f5")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        section.append(detail_table)
        section.append(Spacer(1, 8))
    return section


def report_build_process_section(report_data, styles):
    # 设计说明：测试过程。逐轮的判定轨迹
    # 为什么：报告只说结论会让人怀疑"你到底测了什么"。把每一轮的动作和判定摆出来，
    #         既证明过程真实，也方便对方核对
    section = [PageBreak(), Paragraph("四、测试过程", styles["heading"])]
    recon_block = report_data["recon"]
    round_items = recon_block.get("round_summaries") or []

    if not round_items:
        section.append(Paragraph("本次任务没有留下逐轮记录。", styles["body"]))
        return section

    process_rows = [["轮次", "使用工具", "判定", "理由"]]
    for round_item in round_items:
        verdict = round_item.get("verdict") or {}
        process_rows.append([
            str(round_item.get("round_index")),
            str(round_item.get("tool_name")),
            "发现" if verdict.get("is_vuln") else "无发现",
            str(verdict.get("reason") or "")[:90],
        ])

    process_table = Table(process_rows, colWidths=[12 * mm, 34 * mm, 18 * mm, 92 * mm])
    process_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eeeeee")),
        ("FONTNAME", (0, 0), (-1, -1), styles["body"].fontName),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ALIGN", (0, 0), (0, -1), "CENTER"),
    ]))
    section.append(process_table)

    task_tree = recon_block.get("task_tree") or {}
    if task_tree.get("nodes"):
        section.append(Spacer(1, 8))
        section.append(Paragraph("计划执行情况", styles["heading"]))
        for task_node in task_tree["nodes"]:
            section.append(Paragraph(
                "第 %s 步　%s / %s　状态：%s" % (
                    task_node.get("step_no"),
                    report_parse_safe_text(task_node.get("skill_name")),
                    report_parse_safe_text(task_node.get("tool_name")),
                    report_parse_safe_text(task_node.get("node_status")),
                ), styles["body"]))
    return section


def report_build_appendix_section(report_data, styles):
    # 设计说明：附录。审计日志摘要
    # 为什么：方案里审计日志是不可删除的执行凭据，报告附一份能让整份报告可追溯
    section = [PageBreak(), Paragraph("五、附录：审计日志摘要", styles["heading"])]
    audit_items = report_data["audit"]
    if not audit_items:
        section.append(Paragraph("没有可展示的审计记录。", styles["body"]))
        return section

    for audit_item in audit_items:
        section.append(Paragraph(
            "[%s] %s　%s" % (
                report_parse_safe_text(audit_item["log_type"]),
                report_parse_safe_text(audit_item["created_at"]),
                report_parse_safe_text(audit_item["log_content"]),
            ), styles["body"]))
        if audit_item["log_reason"]:
            section.append(Paragraph(
                "　　%s" % report_parse_safe_text(str(audit_item["log_reason"])[:160]), styles["note"]))
    return section


def report_build_pdf(job_id):
    # 设计说明：报告生成主入口，返回生成结果
    # 为什么：文件名用纯英文——中文文件名在 HTTP 下载头里要额外做编码处理，
    #         一不小心就变成一堆百分号乱码；中文标题放在 PDF 里面更稳当
    # 放弃了：不做报告模板定制。V1.0 版式写死，够用
    report_data = report_fetch_job_data(job_id)
    if report_data is None:
        return {"ok": False, "message": "任务不存在，生成不了报告"}

    font_name = report_register_cjk_font()
    styles = report_build_styles(font_name)
    generated_at = datetime.now().strftime("%Y%m%d%H%M%S")
    report_name = "scan_report_job%s_%s.pdf" % (job_id, generated_at)
    report_path = Path(REPORT_DIR) / report_name

    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        leftMargin=18 * mm, rightMargin=18 * mm, topMargin=20 * mm, bottomMargin=18 * mm,
        title="%s 扫描报告" % APP_NAME,
        author="[著作权人]",
    )

    story = []
    story.extend(report_build_cover_section(report_data, styles))
    story.extend(report_build_summary_section(report_data, styles))
    story.extend(report_build_finding_list_section(report_data, styles))
    story.extend(report_build_finding_detail_section(report_data, styles))
    story.extend(report_build_process_section(report_data, styles))
    story.extend(report_build_appendix_section(report_data, styles))
    document.build(story)

    logger.info("报告已生成：%s（漏洞 %s 条）", report_name, len(report_data["findings"]))
    return {
        "ok": True,
        "message": "报告已生成",
        "file_name": report_name,
        "file_size": report_path.stat().st_size,
        "finding_count": len(report_data["findings"]),
    }


def report_fetch_latest_file(job_id):
    # 设计说明：找出某个任务最新生成的那份报告
    # 为什么：同一个任务可以反复出报告，下载时该拿最新的一份
    report_candidates = sorted(Path(REPORT_DIR).glob("scan_report_job%s_*.pdf" % job_id))
    return report_candidates[-1] if report_candidates else None


def report_fetch_file_list():
    # 设计说明：列出已生成的报告文件，按时间倒序
    # 为什么：报告页要能看到"都出过哪些报告"，光有一个下载按钮不够用
    report_files = sorted(Path(REPORT_DIR).glob("scan_report_job*.pdf"), reverse=True)
    return [
        {
            "file_name": report_file.name,
            "file_size": report_file.stat().st_size,
            "created_at": datetime.fromtimestamp(report_file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        }
        for report_file in report_files
    ]
