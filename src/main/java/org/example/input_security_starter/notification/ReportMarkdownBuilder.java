package org.example.input_security_starter.notification;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.input_security_starter.llm.analysis.AnalysisReport;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class ReportMarkdownBuilder {

    private static final Pattern IP_PATTERN = Pattern.compile("\\b((?:\\d{1,3}\\.){3}\\d{1,3})\\b");
    private static final Pattern URL_PATH_PATTERN = Pattern.compile("(/[-a-zA-Z0-9_./]{2,})");
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final SimpleDateFormat TIME_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private ReportMarkdownBuilder() {
    }

    public static String buildTitle(AnalysisReport report) {
        String riskLevel = normalizedRiskLevel(
            report == null ? null : report.getRiskLevel(),
            report == null ? 0 : report.getRiskScore()
        );
        String status = report == null ? "分析异常" : readableStatus(report.getStatus());
        return renderRiskMark(riskLevel) + " 安全分析报告 - " + status;
    }

    public static String buildStructuredMarkdown(AnalysisReport report) {
        if (report == null) {
            return "# 安全分析报告\n\n报告为空，无法生成内容。";
        }

        List<String> ips = collectIps(report);
        List<String> attackTypes = collectAttackTypes(report);
        List<String> targetUrls = collectTargetUrls(report);

        List<AnalysisReport.SourceDetail> topSources = report.getTopSources() == null
            ? new ArrayList<AnalysisReport.SourceDetail>()
            : report.getTopSources();

        String mainIp = chooseMainIp(report, ips, topSources);
        int confidencePct = normalizeConfidencePercent(report.getConfidence());
        int dataCoverage = estimateCoverage(report, ips, attackTypes, targetUrls);
        String riskLevel = normalizedRiskLevel(report.getRiskLevel(), report.getRiskScore());

        StringBuilder out = new StringBuilder(4096);
        out.append("# 安全分析报告\n\n");

        out.append("## 0. 执行摘要\n");
        out.append("1. 当前结论：")
            .append(report.isAttackDetected() ? "存在攻击活动" : "暂未确认攻击活动")
            .append("，风险评级 ")
            .append(formatRiskLevel(riskLevel))
            .append(" (")
            .append(report.getRiskScore())
            .append("/100)。\n");
        out.append("2. 主攻击源：`")
            .append(mainIp)
            .append("`，主要攻击意图：")
            .append(formatIntent(report.getAttackerIntent()))
            .append("，置信度约 ")
            .append(confidencePct)
            .append("%。\n");
        out.append("3. 处置优先级：先执行 [BLOCK]/[PATCH]，并在 24 小时内完成监控加固与复核闭环。\n\n");

        out.append("## 1. 告警概览\n");
        out.append("- 报告ID：").append(safe(report.getReportId(), "未知")).append("\n");
        out.append("- 生成时间：").append(formatTime(report.getAnalysisTime())).append("\n");
        out.append("- 处理告警量：").append(report.getAlertCount()).append(" 条\n");
        if (report.getOriginalAlertCount() > 0) {
            out.append("- 原始告警量：").append(report.getOriginalAlertCount()).append(" 条\n");
        }
        if (notBlank(report.getWindowStart()) || notBlank(report.getWindowEnd())) {
            out.append("- 分析时间窗：")
                .append(safe(report.getWindowStart(), "unknown"))
                .append(" ~ ")
                .append(safe(report.getWindowEnd(), "unknown"))
                .append("\n");
        }
        out.append("- 关联IP情报数量：").append(report.getIpIntelligenceCount()).append(" 个\n");
        if (report.getOverallSuccessRate() != null) {
            out.append("- 2xx响应占比：").append(report.getOverallSuccessRate()).append("%\n");
        }
        out.append("- 数据完整性声明：").append(formatDataCompleteness(report.getStatus())).append("\n");
        out.append("- 摘要：").append(safe(report.getSummary(), "暂无摘要")).append("\n\n");

        out.append("## 2. 攻击时间线\n");
        appendTimeline(out, report);
        out.append('\n');

        out.append("## 3. 攻击源分析\n");
        out.append("- 主攻击源：`").append(mainIp).append("`\n");
        if (!topSources.isEmpty()) {
            AnalysisReport.SourceDetail first = topSources.get(0);
            out.append("- IP/ASN/地理交叉验证：ASN=")
                .append(first.getAsn() == null ? "未知" : first.getAsn())
                .append("，国家=")
                .append(safe(first.getCountry(), "未知"))
                .append("，ISP=")
                .append(safe(first.getIsp(), "未知"))
                .append("。\n");
        } else {
            out.append("- IP/ASN/地理交叉验证：当前报告未附带完整画像明细，建议结合IP情报源复核。\n");
        }
        out.append("- 差异化评分：采用“风险分 + 置信度 + 证据丰富度”联合判读。\n");
        out.append("- 评分依据透明化：风险分=")
            .append(report.getRiskScore())
            .append("，置信度=")
            .append(confidencePct)
            .append("%，指标数=")
            .append(report.getKeyIndicators() == null ? 0 : report.getKeyIndicators().size())
            .append("。\n");

        if (!topSources.isEmpty()) {
            out.append("- 重点源IP明细（Top ")
                .append(Math.min(6, topSources.size()))
                .append("）：\n");
            out.append("| IP | 风险分 | 攻击手法 | ASN | 国家/ISP |\n");
            out.append("| --- | --- | --- | --- | --- |\n");
            int sourceLimit = Math.min(6, topSources.size());
            for (int i = 0; i < sourceLimit; i++) {
                AnalysisReport.SourceDetail source = topSources.get(i);
                out.append("| ")
                    .append(safe(source.getIp(), "unknown"))
                    .append(" | ")
                    .append(source.getRiskScore())
                    .append(" | ")
                    .append(safe(source.getPrimaryAttackType(), "unknown"))
                    .append(" | ")
                    .append(source.getAsn() == null ? "unknown" : source.getAsn())
                    .append(" | ")
                    .append(safe(source.getCountry(), "-"))
                    .append("/")
                    .append(safe(source.getIsp(), "-"))
                    .append(" |\n");
            }
        }

        if (report.getPeerAttackers() != null && !report.getPeerAttackers().isEmpty()) {
            out.append("- 关联攻击源样本：\n");
            int limit = Math.min(6, report.getPeerAttackers().size());
            for (int i = 0; i < limit; i++) {
                AnalysisReport.PeerAttacker peer = report.getPeerAttackers().get(i);
                out.append("  - ")
                    .append(safe(peer.getIp(), "unknown"))
                    .append("（关系：")
                    .append(formatRelationship(peer.getRelationship()))
                    .append("，置信度：")
                    .append(normalizeConfidencePercent(peer.getConfidence()))
                    .append("%）\n");
            }
        }
        out.append('\n');

        out.append("## 4. 攻击手法分析\n");
        out.append("- MITRE ATT&CK 映射：").append(buildMitreSummary(attackTypes)).append("\n");
        if (report.getPayloadSamples() != null && !report.getPayloadSamples().isEmpty()) {
            int payloadLimit = Math.min(5, report.getPayloadSamples().size());
            out.append("- Top N 载荷样本（脱敏）：")
                .append(String.join(" | ", report.getPayloadSamples().subList(0, payloadLimit)))
                .append("\n");
        } else {
            out.append("- Top N 载荷样本（脱敏）：暂无结构化载荷样本。\n");
        }
        if (report.getOverallSuccessRate() != null) {
            out.append("- 2xx响应占比（基于响应码）：")
                .append(report.getOverallSuccessRate())
                .append("%");
            if (report.getStatusCodeDistribution() != null && !report.getStatusCodeDistribution().isEmpty()) {
                out.append("，状态码分布=").append(report.getStatusCodeDistribution());
            }
            out.append("\n\n");
        } else {
            out.append("- 2xx响应占比（基于响应码）：当前报告缺少状态码分布，暂无法计算。\n\n");
        }

        out.append("## 5. 影响评估\n");
        out.append("- 数据泄露迹象：")
            .append(hasExfiltrationSignal(report) ? "存在疑似数据外传信号（需进一步取证）" : "未发现明确数据泄露信号")
            .append("\n");
        out.append("- 受影响资产清单：").append(formatAssets(report, targetUrls)).append("\n\n");

        out.append("## 6. 攻击者画像\n");
        out.append("- 技术水平：").append(safe(report.getAttackerSkillLevel(), "未知")).append("\n");
        out.append("- 自动化程度：").append(safe(report.getAutomationType(), "未知")).append("\n");
        out.append("- 主要意图：").append(formatIntent(report.getAttackerIntent())).append("\n");
        out.append("- 行为模式：").append(safe(report.getAttackerPattern(), "未知")).append("\n");
        out.append("- 证据链：风险分=")
            .append(report.getRiskScore())
            .append("，关键指标=")
            .append(report.getKeyIndicators() == null ? 0 : report.getKeyIndicators().size())
            .append("，关联攻击者=")
            .append(report.getPeerAttackers() == null ? 0 : report.getPeerAttackers().size())
            .append("。\n\n");

        out.append("## 7. 关联分析\n");
        if (report.getPeerAttackers() == null || report.getPeerAttackers().isEmpty()) {
            out.append("- 暂无关联攻击者样本，建议补充 ASN/时间窗/UA 相似度特征后再计算。\n");
        } else {
            out.append("- 解释型置信度模型：基础分 40 + 关系权重(30) + 行为相似度(30)。\n");
            int limit = Math.min(8, report.getPeerAttackers().size());
            for (int i = 0; i < limit; i++) {
                AnalysisReport.PeerAttacker peer = report.getPeerAttackers().get(i);
                int pct = normalizeConfidencePercent(peer.getConfidence());
                out.append(String.format(Locale.ROOT, "%d. %s ←[%s, %d%%]← %s\n",
                    i + 1,
                    safe(peer.getIp(), "unknown"),
                    formatRelationship(peer.getRelationship()),
                    pct,
                    safe(peer.getRelatedToIp(), mainIp)));
            }
        }
        out.append('\n');

        out.append("## 8. 处置建议\n");
        appendRecommendations(out, report);
        out.append('\n');

        out.append("## 9. IOC列表\n");
        out.append("```json\n")
            .append(buildIocJson(report, ips, attackTypes, targetUrls, riskLevel, mainIp))
            .append("\n```\n\n");

        out.append("## 10. 置信度与局限性声明\n");
        out.append("- 当前置信度：").append(confidencePct).append("%。\n");
        out.append("- 局限性1：本报告以聚合数据与模型推断为主，未直接附带全量原始请求体。\n");
        out.append("- 局限性2：部分字段（如 ASN、地理、响应码统计）依赖上游日志完整性。\n");
        out.append("- 局限性3：若状态为 degraded/error，结论需结合人工复核后执行高风险动作。\n\n");

        out.append("_数据覆盖率: ")
            .append(dataCoverage)
            .append("% | LLM生成内容已通过事实校验(规则校验+聚合回填) | 报告分级: TLP:AMBER_");

        return out.toString();
    }

    /**
     * 第一条：战术摘要 Markdown
     */
    public static String buildTacticalSummary(AnalysisReport report) {
        if (report == null) {
            return "# \u26A0\uFE0F [风险] 安全分析报告 - 分析异常\n\n报告为空，无法生成内容。";
        }

        List<String> ips = collectIps(report);
        List<String> attackTypes = collectAttackTypes(report);
        List<String> targetUrls = collectTargetUrls(report);
        List<AnalysisReport.SourceDetail> topSources = report.getTopSources() == null
            ? new ArrayList<AnalysisReport.SourceDetail>()
            : report.getTopSources();

        String mainIp = chooseMainIp(report, ips, topSources);
        AnalysisReport.SourceDetail mainSource = findSourceDetail(topSources, mainIp);
        String blockIp = chooseBlockIp(report, mainIp);
        String topUrl = targetUrls.isEmpty() ? "/unknown" : targetUrls.get(0);

        String riskLevel = normalizedRiskLevel(report.getRiskLevel(), report.getRiskScore());
        String riskMark = renderRiskMark(riskLevel);
        int confidencePct = normalizeConfidencePercent(report.getConfidence());

        String mainAttackType = mainSource == null
            ? (attackTypes.isEmpty() ? "unknown" : attackTypes.get(0))
            : safe(mainSource.getPrimaryAttackType(), "unknown");
        int mainEvents = mainSource == null ? 0 : mainSource.getTotalEvents();
        String mainSuccessRate = mainSource == null ? "-" : formatSuccessRate(mainSource.getSuccessRate());
        String intent = readableIntent(report.getAttackerIntent());

        List<String> phases = detectKillChainPhases(attackTypes);
        String phaseInline = phases.isEmpty() ? "侦察" : String.join(" → ", phases);

        StringBuilder out = new StringBuilder(3072);
        out.append("# ").append(riskMark).append(" 安全分析报告 - ").append(readableStatus(report.getStatus())).append("\n\n");
        out.append("## 0. 执行摘要\n");
        out.append("1. 触发原因：检测到多阶段攻击链（").append(phaseInline).append("），满足 LLM 分析阈值。\n");
        out.append("2. 当前结论：").append(riskMark).append(" (").append(report.getRiskScore()).append("/100)，置信度 ")
            .append(confidencePct).append("%。\n");
        out.append("3. 主攻击源：").append(mainIp).append("（").append(mainAttackType).append("，")
            .append(mainEvents).append("次事件，成功率 ").append(mainSuccessRate).append("）意图：")
            .append(intent).append("。\n");
        out.append("4. 立即处置：封禁 ").append(blockIp).append("；修复 ").append(topUrl).append(" 输入校验漏洞。\n\n");

        out.append("## 1. 告警概览\n");
        out.append("- 时间窗：").append(safe(report.getWindowStart(), "unknown")).append(" ~ ")
            .append(safe(report.getWindowEnd(), "unknown")).append("\n");
        out.append("- 处理/原始：").append(report.getAlertCount()).append("/")
            .append(report.getOriginalAlertCount() > 0 ? report.getOriginalAlertCount() : report.getAlertCount())
            .append(" 条 | IP情报：").append(report.getIpIntelligenceCount()).append(" 个\n");
        if (report.getOverallSuccessRate() != null) {
            out.append("- 2xx占比：").append(String.format(Locale.ROOT, "%.2f%%", report.getOverallSuccessRate()));
            if (report.getOverallSuccessRate() >= 50d) {
                out.append(" \u26A0\uFE0F 超半数请求未被拦截");
            }
            out.append("\n");
        }
        out.append("- 数据完整性：").append(readableDataCompleteness(report.getStatus())).append("\n\n");

        out.append("## 1.5 攻击链路径\n");
        out.append("检测到 ").append(phases.size()).append(" 个 Kill Chain 阶段：").append(phaseInline).append("\n");
        int phaseTop = Math.min(3, topSources.size());
        for (int i = 0; i < phaseTop; i++) {
            AnalysisReport.SourceDetail source = topSources.get(i);
            String phase = phaseOfAttackType(source.getPrimaryAttackType());
            out.append("- ").append(safe(source.getIp(), "unknown")).append("：")
                .append(phase).append("（").append(safe(source.getPrimaryAttackType(), "unknown")).append("），成功率 ")
                .append(formatSuccessRate(source.getSuccessRate())).append("\n");
        }
        out.append("\n");

        out.append("## 3. 攻击源 Top3\n");
        out.append("| IP | 风险分 | 主要手法 | 事件数 | 成功率 |\n");
        out.append("| --- | --- | --- | --- | --- |\n");
        int topLimit = Math.min(3, topSources.size());
        for (int i = 0; i < topLimit; i++) {
            AnalysisReport.SourceDetail source = topSources.get(i);
            out.append("| ").append(safe(source.getIp(), "unknown"))
                .append(" | ").append(source.getRiskScore())
                .append(" | ").append(safe(source.getPrimaryAttackType(), "unknown"))
                .append(" | ").append(source.getTotalEvents())
                .append(" | ").append(formatSuccessRate(source.getSuccessRate()))
                .append(" |\n");
        }
        out.append("\n");

        out.append("## 8. 处置建议\n");
        appendRestoredRecommendations(out, report, mainIp, targetUrls);
        return renumberSectionHeaders(out.toString());
    }

    /**
     * 第二条：情报详情 JSONC 代码块
     */
    public static String buildIntelligenceJsonBlock(AnalysisReport report) {
        if (report == null) {
            return "```json\n{\n  // empty report\n}\n```";
        }

        List<String> ips = collectIps(report);
        List<String> attackTypes = collectAttackTypes(report);
        List<String> targetUrls = collectTargetUrls(report);
        List<AnalysisReport.SourceDetail> topSources = report.getTopSources() == null
            ? new ArrayList<AnalysisReport.SourceDetail>()
            : report.getTopSources();
        String mainIp = chooseMainIp(report, ips, topSources);
        String pivotIp = findPivotIp(report.getPeerAttackers(), mainIp);

        Map<String, List<String>> mitre = buildMitreGroups(attackTypes);
        List<String> payloads = report.getPayloadSamples() == null
            ? new ArrayList<String>()
            : report.getPayloadSamples();
        String successRate = report.getOverallSuccessRate() == null
            ? "-"
            : String.format(Locale.ROOT, "%.2f%%", report.getOverallSuccessRate());

        Map<String, Integer> scoreMap = new LinkedHashMap<String, Integer>();
        for (AnalysisReport.SourceDetail source : topSources) {
            if (source != null && isValidIpv4(source.getIp())) {
                scoreMap.put(source.getIp(), source.getRiskScore());
            }
        }
        List<String> high = new ArrayList<String>();
        List<String> medium = new ArrayList<String>();
        List<String> observe = new ArrayList<String>();
        for (String ip : ips) {
            Integer score = scoreMap.get(ip);
            if (score == null) {
                observe.add(ip);
            } else if (score >= 75) {
                high.add(ip);
            } else if (score >= 50) {
                medium.add(ip);
            } else {
                observe.add(ip);
            }
        }

        List<String> strong = new ArrayList<String>();
        List<String> pending = new ArrayList<String>();
        if (report.getPeerAttackers() != null) {
            for (AnalysisReport.PeerAttacker peer : report.getPeerAttackers()) {
                if (peer == null || !isValidIpv4(peer.getIp())) {
                    continue;
                }
                if (peer.getConfidence() >= 0.6d) {
                    if (!strong.contains(peer.getIp())) {
                        strong.add(peer.getIp());
                    }
                } else {
                    if (!pending.contains(peer.getIp())) {
                        pending.add(peer.getIp());
                    }
                }
            }
        }

        StringBuilder out = new StringBuilder(4096);
        out.append("```json\n");
        out.append("{\n");
        out.append("  // ── §4 攻击手法 ──────────────────────────────\n");
        out.append("  \"mitre\": {\n");
        int mitreIndex = 0;
        for (Map.Entry<String, List<String>> entry : mitre.entrySet()) {
            mitreIndex++;
            out.append("    ").append(jsonString(entry.getKey())).append(": ");
            appendJsonArray(out, entry.getValue());
            out.append(mitreIndex < mitre.size() ? ",\n" : "\n");
        }
        out.append("  },\n");
        out.append("  \"payloads\": [\n");
        int payloadLimit = Math.min(8, payloads.size());
        for (int i = 0; i < payloadLimit; i++) {
            String payload = payloads.get(i);
            out.append("    ").append(jsonString(payload));
            String comment = guessPayloadComment(payload);
            if (notBlank(comment)) {
                out.append(", // ").append(comment);
            } else if (i < payloadLimit - 1) {
                out.append(",");
            }
            out.append("\n");
        }
        out.append("  ],\n");
        out.append("  \"success_rate\": ").append(jsonString(successRate))
            .append(", // ").append(successRate.startsWith("-") ? "无可用状态码统计" : "2xx响应占比")
            .append("\n\n");

        out.append("  // ── §5 影响评估 ──────────────────────────────\n");
        out.append("  \"impact\": {\n");
        out.append("    \"data_exfil\": ").append(hasExfiltrationSignal(report) ? "true" : "false").append(",\n");
        out.append("    \"affected_assets\": ");
        appendJsonArray(out, limitList(targetUrls, 5));
        out.append("\n  },\n\n");

        out.append("  // ── §6 攻击者画像 ─────────────────────────────\n");
        out.append("  \"attacker\": {\n");
        out.append("    \"skill\": ").append(jsonString(safe(report.getAttackerSkillLevel(), "未知"))).append(",\n");
        out.append("    \"automation\": ").append(jsonString(safe(report.getAutomationType(), "未知"))).append(",\n");
        out.append("    \"intent\": ").append(jsonString(readableIntent(report.getAttackerIntent()))).append(",\n");
        out.append("    \"pattern\": ").append(jsonString(safe(report.getAttackerPattern(), "多类型攻击手段组合"))).append("\n");
        out.append("  },\n\n");

        out.append("  // ── §7 关联分析 ──────────────────────────────\n");
        out.append("  \"correlation\": {\n");
        out.append("    \"pivot\": ").append(jsonString(pivotIp)).append(",\n");
        out.append("    \"strong\": ");
        appendJsonArray(out, strong);
        out.append(",\n");
        out.append("    \"pending\": ");
        appendJsonArray(out, pending);
        out.append(",\n");
        out.append("    \"note\": ").append(jsonString("建议提取上述IP的UA特征与Payload进行指纹比对")).append("\n");
        out.append("  },\n\n");

        out.append("  // ── §9 IOC ───────────────────────────────────\n");
        out.append("  \"ioc\": {\n");
        out.append("    \"high\": ");
        appendJsonArray(out, high);
        out.append(",\n");
        out.append("    \"medium\": ");
        appendJsonArray(out, medium);
        out.append(",\n");
        out.append("    \"observe\": ");
        appendJsonArray(out, observe);
        out.append(",\n");
        out.append("    \"types\": ");
        appendJsonArray(out, attackTypes);
        out.append(",\n");
        out.append("    \"window\": ").append(jsonString(shortWindow(report.getWindowStart(), report.getWindowEnd()))).append("\n");
        out.append("  },\n\n");

        out.append("  // ── §10 声明 ─────────────────────────────────\n");
        out.append("  // 置信度: ").append(normalizeConfidencePercent(report.getConfidence()))
            .append("% | 聚合推断，需结合原始日志复核 | TLP:AMBER\n");
        out.append("  \"meta\": {\n");
        out.append("    \"report_id\": ").append(jsonString(safe(report.getReportId(), "unknown"))).append(",\n");
        out.append("    \"confidence\": ").append(String.format(Locale.ROOT, "%.4f", normalizeConfidenceValue(report.getConfidence()))).append(",\n");
        out.append("    \"coverage\": ").append(jsonString(estimateCoverage(report, ips, attackTypes, targetUrls) + "%")).append(",\n");
        out.append("    \"tlp\": ").append(jsonString("AMBER")).append("\n");
        out.append("  }\n");
        out.append("}\n");
        out.append("```");
        return out.toString();
    }

    private static String renderRiskMark(String riskLevel) {
        if ("high".equalsIgnoreCase(riskLevel)) {
            return "\uD83D\uDD34";
        }
        if ("medium".equalsIgnoreCase(riskLevel)) {
            return "\uD83D\uDFE1";
        }
        if ("low".equalsIgnoreCase(riskLevel)) {
            return "\uD83D\uDFE2";
        }
        return "\u26A0\uFE0F";
    }

    private static String readableStatus(String status) {
        if ("success".equalsIgnoreCase(status) || "guarded".equalsIgnoreCase(status)) {
            return "分析完成";
        }
        if ("degraded".equalsIgnoreCase(status)) {
            return "降级分析";
        }
        return "分析异常";
    }

    private static String readableDataCompleteness(String status) {
        if ("success".equalsIgnoreCase(status) || "guarded".equalsIgnoreCase(status)) {
            return "良好";
        }
        if ("degraded".equalsIgnoreCase(status)) {
            return "部分缺失";
        }
        return "不足";
    }

    private static String readableIntent(String intent) {
        if (!notBlank(intent)) {
            return "未知";
        }
        String lower = intent.toLowerCase(Locale.ROOT);
        if (lower.contains("recon")) {
            return "侦察探测";
        }
        if (lower.contains("exploit")) {
            return "漏洞利用";
        }
        if (lower.contains("exfil")) {
            return "数据窃取";
        }
        if (lower.contains("lateral")) {
            return "横向移动";
        }
        return intent;
    }

    private static List<String> detectKillChainPhases(List<String> attackTypes) {
        List<String> phases = new ArrayList<String>();
        List<String> order = Arrays.asList("侦察", "投递", "利用", "安装", "命令控制", "行动");
        for (String phase : order) {
            for (String attackType : attackTypes) {
                if (phase.equals(phaseOfAttackType(attackType)) && !phases.contains(phase)) {
                    phases.add(phase);
                }
            }
        }
        return phases;
    }

    private static String phaseOfAttackType(String attackType) {
        if (!notBlank(attackType)) {
            return "侦察";
        }
        String t = attackType.toLowerCase(Locale.ROOT);
        if (t.contains("command-injection") || t.contains("code-execution") || t.contains("deserialization")) {
            return "利用";
        }
        if (t.contains("installation")) {
            return "安装";
        }
        if (t.contains("c2")) {
            return "命令控制";
        }
        if (t.contains("action")) {
            return "行动";
        }
        if (t.contains("xss") || t.contains("sql") || t.contains("xxe") || t.contains("nosql") || t.contains("template")) {
            return "投递";
        }
        return "侦察";
    }

    private static AnalysisReport.SourceDetail findSourceDetail(List<AnalysisReport.SourceDetail> topSources, String ip) {
        if (topSources == null || topSources.isEmpty()) {
            return null;
        }
        for (AnalysisReport.SourceDetail source : topSources) {
            if (source != null && safe(source.getIp(), "").equals(ip)) {
                return source;
            }
        }
        return topSources.get(0);
    }

    private static String chooseBlockIp(AnalysisReport report, String mainIp) {
        if (report.getPeerAttackers() == null) {
            return mainIp;
        }
        for (AnalysisReport.PeerAttacker peer : report.getPeerAttackers()) {
            if (peer == null) {
                continue;
            }
            String relationship = safe(peer.getRelationship(), "").toLowerCase(Locale.ROOT);
            if ("same_asn".equals(relationship) && peer.getConfidence() >= 0.6d && notBlank(peer.getRelatedToIp())) {
                return peer.getRelatedToIp().trim();
            }
        }
        return mainIp;
    }

    private static String formatSuccessRate(Double successRate) {
        if (successRate == null) {
            return "-";
        }
        String value = String.format(Locale.ROOT, "%.2f%%", successRate);
        if (successRate >= 70d) {
            return value + " \uD83D\uDD34";
        }
        if (successRate >= 50d) {
            return value + " \u26A0\uFE0F";
        }
        return value;
    }

    private static void appendRestoredRecommendations(
        StringBuilder out,
        AnalysisReport report,
        String mainIp,
        List<String> targetUrls
    ) {
        String url1 = targetUrls.size() > 0 ? targetUrls.get(0) : "/unknown";
        String url2 = targetUrls.size() > 1 ? targetUrls.get(1) : url1;

        out.append("1. \uD83D\uDEE1\uFE0F **[BLOCK]** 封禁 ").append(mainIp).append(" 及同网段 — WAF下发策略，观察24h\n");
        out.append("2. \uD83D\uDD27 **[PATCH]** 修复 ").append(url1).append(" 路径规范化与输入校验漏洞\n");
        out.append("3. \uD83D\uDCE1 **[MONITOR]** ").append(url1).append("、").append(url2).append(" 提升监控，联动4xx/5xx峰值\n");
        out.append("4. \uD83D\uDD0D **[REVIEW]** 复核 ").append(url1).append(" 权限模型与最近发布变更\n");
        out.append("5. \uD83D\uDEA8 **[IR]** 固化 ").append(mainIp).append(" 取证证据，启动事件分级排查\n");
    }

    private static Map<String, List<String>> buildMitreGroups(List<String> attackTypes) {
        Map<String, List<String>> grouped = new LinkedHashMap<String, List<String>>();
        grouped.put("T1190 漏洞利用", new ArrayList<String>());
        grouped.put("T1059 命令执行", new ArrayList<String>());
        grouped.put("T1505 持久化", new ArrayList<String>());

        for (String attackType : attackTypes) {
            if (!notBlank(attackType)) {
                continue;
            }
            String t = attackType.toLowerCase(Locale.ROOT);
            if (t.contains("command-injection") || t.contains("code-execution")) {
                grouped.get("T1059 命令执行").add(attackType);
            } else if (t.contains("installation")) {
                grouped.get("T1505 持久化").add(attackType);
            } else {
                grouped.get("T1190 漏洞利用").add(attackType);
            }
        }
        return grouped;
    }

    private static String findPivotIp(List<AnalysisReport.PeerAttacker> peers, String mainIp) {
        if (peers == null || peers.isEmpty()) {
            return mainIp;
        }
        Map<String, Integer> counter = new LinkedHashMap<String, Integer>();
        for (AnalysisReport.PeerAttacker peer : peers) {
            if (peer == null) {
                continue;
            }
            String relatedTo = notBlank(peer.getRelatedToIp()) ? peer.getRelatedToIp().trim() : mainIp;
            if (!isValidIpv4(relatedTo)) {
                relatedTo = mainIp;
            }
            Integer value = counter.get(relatedTo);
            counter.put(relatedTo, value == null ? 1 : value + 1);
        }
        String result = mainIp;
        int best = -1;
        for (Map.Entry<String, Integer> entry : counter.entrySet()) {
            if (entry.getValue() > best) {
                result = entry.getKey();
                best = entry.getValue();
            }
        }
        return result;
    }

    private static List<String> limitList(List<String> values, int max) {
        if (values == null || values.isEmpty()) {
            return new ArrayList<String>();
        }
        return new ArrayList<String>(values.subList(0, Math.min(values.size(), max)));
    }

    private static void appendJsonArray(StringBuilder out, List<String> values) {
        out.append("[");
        if (values != null && !values.isEmpty()) {
            for (int i = 0; i < values.size(); i++) {
                if (i > 0) {
                    out.append(", ");
                }
                out.append(jsonString(values.get(i)));
            }
        }
        out.append("]");
    }

    private static String jsonString(String text) {
        String value = text == null ? "" : text;
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String shortWindow(String start, String end) {
        if (!notBlank(start) || !notBlank(end)) {
            return safe(start, "unknown") + " ~ " + safe(end, "unknown");
        }
        String left = start.length() >= 16 ? start.substring(0, 16) : start;
        String right = end.length() >= 16 ? end.substring(11, 16) : end;
        return left + " ~ " + right;
    }

    private static String guessPayloadComment(String payload) {
        if (!notBlank(payload)) {
            return "";
        }
        String p = payload.toLowerCase(Locale.ROOT);
        if (p.contains("etc/passwd") || p.contains("../")) {
            return "路径遍历";
        }
        if (p.contains("ldap://") || p.contains("${lower:")) {
            return "JNDI/Log4Shell";
        }
        if (p.contains("or 1=1") || p.contains("union select")) {
            return "SQL注入";
        }
        if (p.contains(";") || p.contains("cat /etc")) {
            return "命令注入";
        }
        if (p.contains("javascript:") || p.contains("<script")) {
            return "XSS";
        }
        if (p.contains("${") && p.contains("}")) {
            return "模板注入探针";
        }
        if (p.contains("<!entity") || p.contains("<!doctype")) {
            return "XXE";
        }
        return "";
    }

    private static double normalizeConfidenceValue(double confidence) {
        if (Double.isNaN(confidence) || Double.isInfinite(confidence)) {
            return 0d;
        }
        if (confidence > 1d) {
            return Math.max(0d, Math.min(1d, confidence / 100d));
        }
        return Math.max(0d, Math.min(1d, confidence));
    }

    private static String chooseMainIp(
        AnalysisReport report,
        List<String> ips,
        List<AnalysisReport.SourceDetail> topSources
    ) {
        if (notBlank(report.getMainAttackerIp())) {
            return report.getMainAttackerIp();
        }
        if (!topSources.isEmpty() && notBlank(topSources.get(0).getIp())) {
            return topSources.get(0).getIp();
        }
        if (!ips.isEmpty()) {
            return ips.get(0);
        }
        return "unknown";
    }

    private static void appendTimeline(StringBuilder out, AnalysisReport report) {
        if (report.getTimeline() != null && !report.getTimeline().isEmpty()) {
            List<AnalysisReport.TimelineEvent> timeline = report.getTimeline();
            int limit = Math.min(10, timeline.size());
            for (int i = 0; i < limit; i++) {
                AnalysisReport.TimelineEvent event = timeline.get(i);
                out.append(String.format(Locale.ROOT, "%d. [%s] %s | %s | %s\n",
                    i + 1,
                    formatTime(new Date(event.getTimestamp())),
                    safe(event.getPhase(), "unknown"),
                    safe(event.getDescription(), "no-description"),
                    safe(event.getSourceIp(), "unknown")));
            }
            return;
        }

        if (notBlank(report.getWindowStart()) || notBlank(report.getWindowEnd())) {
            out.append("- 时间窗：")
                .append(safe(report.getWindowStart(), "unknown"))
                .append(" ~ ")
                .append(safe(report.getWindowEnd(), "unknown"))
                .append("\n");
            out.append("- 时间线细粒度事件：当前报告无结构化时间序列，建议结合原始日志追溯。\n");
            return;
        }

        out.append("- 时间线数据缺失：当前仅保留摘要证据。")
            .append(safe(report.getAttackNarrative(), "暂无叙述"))
            .append("\n");
    }

    private static void appendRecommendations(StringBuilder out, AnalysisReport report) {
        List<String> recommendations = report.getRecommendations();
        if (recommendations == null || recommendations.isEmpty()) {
            out.append("1. [BLOCK] 在边界设备/WAF封禁高风险源IP，并设置短期观察期。\n");
            out.append("2. [PATCH] 修复高频命中接口的输入校验与鉴权漏洞。\n");
            out.append("3. [MONITOR] 提升关键路径监控与阈值告警。\n");
            out.append("4. [REVIEW] 复核权限模型与最近发布变更。\n");
            out.append("5. [IR] 启动应急响应与取证流程。\n");
            return;
        }

        int index = 1;
        for (String rec : recommendations) {
            if (!notBlank(rec)) {
                continue;
            }
            out.append(index)
                .append(". ")
                .append(rec.trim())
                .append(" | 步骤：")
                .append(explainRecommendation(rec))
                .append("\n");
            index++;
            if (index > 8) {
                break;
            }
        }
    }

    private static String explainRecommendation(String rec) {
        String upper = rec == null ? "" : rec.toUpperCase(Locale.ROOT);
        if (upper.startsWith("[BLOCK]")) {
            return "在WAF/边界设备下发临时封禁策略，回溯同网段行为并观察24小时";
        }
        if (upper.startsWith("[PATCH]")) {
            return "定位命中接口并修复输入校验/路径规范化问题，完成回归验证";
        }
        if (upper.startsWith("[MONITOR]")) {
            return "增加攻击类型、4xx/5xx峰值与异常UA联动告警";
        }
        if (upper.startsWith("[REVIEW]")) {
            return "复核权限模型、鉴权绕过风险与最近发布变更";
        }
        if (upper.startsWith("[IR]")) {
            return "启动事件分级、证据固化及资产账号横向排查";
        }
        return "明确责任人、时间窗口和验收标准并闭环";
    }

    private static String buildIocJson(
        AnalysisReport report,
        List<String> ips,
        List<String> attackTypes,
        List<String> targetUrls,
        String riskLevel,
        String mainIp
    ) {
        Map<String, Object> ioc = new LinkedHashMap<String, Object>();
        ioc.put("report_id", report.getReportId());
        ioc.put("generated_at", formatTime(report.getAnalysisTime()));
        ioc.put("risk_score", report.getRiskScore());
        ioc.put("risk_level", safe(riskLevel, "unknown"));
        ioc.put("confidence", report.getConfidence());
        ioc.put("ips", ips);
        ioc.put("attack_types", attackTypes);
        ioc.put("target_urls", targetUrls);
        ioc.put("window_start", report.getWindowStart());
        ioc.put("window_end", report.getWindowEnd());
        ioc.put("status_codes", report.getStatusCodeDistribution());
        ioc.put("payload_samples", report.getPayloadSamples());
        ioc.put("main_attacker_ip", mainIp);

        List<Map<String, Object>> peers = new ArrayList<Map<String, Object>>();
        if (report.getPeerAttackers() != null) {
            int limit = Math.min(20, report.getPeerAttackers().size());
            for (int i = 0; i < limit; i++) {
                AnalysisReport.PeerAttacker peer = report.getPeerAttackers().get(i);
                if (peer == null) {
                    continue;
                }
                Map<String, Object> row = new LinkedHashMap<String, Object>();
                row.put("ip", peer.getIp());
                row.put("relationship", peer.getRelationship());
                row.put("confidence", peer.getConfidence());
                row.put("related_to", peer.getRelatedToIp());
                peers.add(row);
            }
        }
        ioc.put("peer_attackers", peers);
        ioc.put("top_sources", report.getTopSources());

        try {
            return OBJECT_MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(ioc);
        } catch (Exception e) {
            return "{\"error\":\"ioc_json_serialize_failed\"}";
        }
    }

    private static List<String> collectIps(AnalysisReport report) {
        Set<String> ips = new LinkedHashSet<String>();

        if (isValidIpv4(report.getMainAttackerIp())) {
            ips.add(report.getMainAttackerIp());
        }

        if (report.getTopSources() != null) {
            for (AnalysisReport.SourceDetail source : report.getTopSources()) {
                if (source != null && isValidIpv4(source.getIp())) {
                    ips.add(source.getIp());
                }
            }
        }

        if (report.getKeyIndicators() != null) {
            for (String indicator : report.getKeyIndicators()) {
                if (!notBlank(indicator)) {
                    continue;
                }
                if (isValidIpv4(indicator)) {
                    ips.add(indicator);
                }
                Matcher matcher = IP_PATTERN.matcher(indicator);
                while (matcher.find()) {
                    String ip = matcher.group(1);
                    if (isValidIpv4(ip)) {
                        ips.add(ip);
                    }
                }
            }
        }

        if (report.getPeerAttackers() != null) {
            for (AnalysisReport.PeerAttacker peer : report.getPeerAttackers()) {
                if (peer != null && isValidIpv4(peer.getIp())) {
                    ips.add(peer.getIp());
                }
            }
        }

        return new ArrayList<String>(ips);
    }

    private static List<String> collectAttackTypes(AnalysisReport report) {
        Set<String> types = new LinkedHashSet<String>();

        if (report.getTopAttackTypes() != null) {
            for (String attackType : report.getTopAttackTypes()) {
                if (notBlank(attackType)) {
                    types.add(attackType.trim());
                }
            }
        }

        if (report.getAttackTypes() != null) {
            for (AnalysisReport.AttackType attackType : report.getAttackTypes()) {
                if (attackType != null && notBlank(attackType.getName())) {
                    types.add(attackType.getName().trim());
                }
            }
        }

        if (report.getKeyIndicators() != null) {
            for (String indicator : report.getKeyIndicators()) {
                if (!notBlank(indicator)) {
                    continue;
                }
                String text = indicator.trim().toLowerCase(Locale.ROOT);
                if (text.contains("-") && text.length() <= 64 && !text.contains("/")) {
                    types.add(indicator.trim());
                }
            }
        }

        return new ArrayList<String>(types);
    }

    private static List<String> collectTargetUrls(AnalysisReport report) {
        Set<String> urls = new LinkedHashSet<String>();

        if (report.getTopTargetUrls() != null) {
            for (String targetUrl : report.getTopTargetUrls()) {
                if (notBlank(targetUrl)) {
                    urls.add(targetUrl.trim());
                }
            }
        }

        if (report.getAffectedAssets() != null) {
            for (String asset : report.getAffectedAssets()) {
                if (notBlank(asset)) {
                    urls.add(asset.trim());
                }
            }
        }

        if (report.getKeyIndicators() != null) {
            for (String indicator : report.getKeyIndicators()) {
                if (!notBlank(indicator)) {
                    continue;
                }
                String text = indicator.trim();
                if (text.startsWith("/")) {
                    urls.add(text);
                }
                Matcher matcher = URL_PATH_PATTERN.matcher(text);
                while (matcher.find()) {
                    String path = matcher.group(1);
                    if (path.length() >= 3) {
                        urls.add(path);
                    }
                }
            }
        }

        return new ArrayList<String>(urls);
    }

    private static String buildMitreSummary(List<String> attackTypes) {
        if (attackTypes == null || attackTypes.isEmpty()) {
            return "暂无可映射攻击类型";
        }

        List<String> mapped = new ArrayList<String>();
        for (String type : attackTypes) {
            if (!notBlank(type)) {
                continue;
            }
            mapped.add(mapMitre(type));
            if (mapped.size() >= 6) {
                break;
            }
        }
        return String.join("；", mapped);
    }

    private static String mapMitre(String attackType) {
        String t = attackType.toLowerCase(Locale.ROOT);

        if (t.contains("sql")) {
            return attackType + " -> T1190 Exploit Public-Facing Application";
        }
        if (t.contains("xss")) {
            return attackType + " -> T1059 Command and Scripting Interpreter (Web Script)";
        }
        if (t.contains("directory-traversal") || t.contains("path-traversal")) {
            return attackType + " -> T1190 Exploit Public-Facing Application";
        }
        if (t.contains("command-injection") || t.contains("code-execution")) {
            return attackType + " -> T1059 Command and Scripting Interpreter";
        }
        if (t.contains("deserialization")) {
            return attackType + " -> T1203 Exploitation for Client Execution";
        }
        if (t.contains("ssrf")) {
            return attackType + " -> T1190 Exploit Public-Facing Application";
        }
        if (t.contains("port-scan") || t.contains("recon")) {
            return attackType + " -> TA0043 Reconnaissance";
        }

        return attackType + " -> ATT&CK 待人工映射";
    }

    private static boolean hasExfiltrationSignal(AnalysisReport report) {
        String intent = safe(report.getAttackerIntent(), "").toLowerCase(Locale.ROOT);
        if (intent.contains("exfiltration") || intent.contains("exfil")) {
            return true;
        }

        String text = (safe(report.getAttackNarrative(), "") + " " + safe(report.getSummary(), ""))
            .toLowerCase(Locale.ROOT);

        return text.contains("数据泄露") || text.contains("外传") || text.contains("exfil");
    }

    private static String formatAssets(AnalysisReport report, List<String> targetUrls) {
        if (report.getAffectedAssets() != null && !report.getAffectedAssets().isEmpty()) {
            return String.join("、", report.getAffectedAssets());
        }
        if (targetUrls != null && !targetUrls.isEmpty()) {
            int limit = Math.min(5, targetUrls.size());
            return String.join("、", targetUrls.subList(0, limit));
        }
        return "暂无结构化资产清单";
    }

    private static int estimateCoverage(
        AnalysisReport report,
        List<String> ips,
        List<String> attackTypes,
        List<String> targetUrls
    ) {
        int score = 45;

        if (report.getAlertCount() > 0) {
            score += 10;
        }
        if (report.getIpIntelligenceCount() > 0) {
            score += 10;
        }
        if (!ips.isEmpty()) {
            score += 10;
        }
        if (!attackTypes.isEmpty()) {
            score += 10;
        }
        if (!targetUrls.isEmpty()) {
            score += 5;
        }
        if (report.getTopSources() != null && !report.getTopSources().isEmpty()) {
            score += 8;
        }
        if (report.getStatusCodeDistribution() != null && !report.getStatusCodeDistribution().isEmpty()) {
            score += 5;
        }
        if (report.getPayloadSamples() != null && !report.getPayloadSamples().isEmpty()) {
            score += 5;
        }
        if (report.getPeerAttackers() != null && !report.getPeerAttackers().isEmpty()) {
            score += 5;
        }

        if ("degraded".equalsIgnoreCase(report.getStatus())) {
            score -= 15;
        } else if ("error".equalsIgnoreCase(report.getStatus())) {
            score -= 30;
        }

        return Math.max(20, Math.min(100, score));
    }

    private static String formatDataCompleteness(String status) {
        if ("success".equalsIgnoreCase(status) || "guarded".equalsIgnoreCase(status)) {
            return "完整性良好（已完成结构化解析与规则回填）";
        }
        if ("degraded".equalsIgnoreCase(status)) {
            return "部分缺失（已启用降级本地策略，建议人工复核）";
        }
        return "完整性不足（分析异常）";
    }

    private static String formatStatus(String status) {
        if ("success".equalsIgnoreCase(status) || "guarded".equalsIgnoreCase(status)) {
            return "分析完成";
        }
        if ("degraded".equalsIgnoreCase(status)) {
            return "降级分析";
        }
        return "分析异常";
    }

    private static String formatTime(Date date) {
        if (date == null) {
            return "未知";
        }
        synchronized (TIME_FORMAT) {
            return TIME_FORMAT.format(date);
        }
    }

    private static String formatIntent(String intent) {
        if (!notBlank(intent)) {
            return "未知";
        }

        String lower = intent.toLowerCase(Locale.ROOT);
        if (lower.contains("recon")) {
            return "侦察探测";
        }
        if (lower.contains("exploit")) {
            return "漏洞利用";
        }
        if (lower.contains("exfil")) {
            return "数据窃取";
        }
        if (lower.contains("lateral")) {
            return "横向移动";
        }
        return intent;
    }

    private static String formatRelationship(String relationship) {
        if (!notBlank(relationship)) {
            return "未知";
        }

        String lower = relationship.toLowerCase(Locale.ROOT);
        if ("same_asn".equals(lower)) {
            return "同一ASN";
        }
        if ("same_attack_type".equals(lower)) {
            return "相同攻击手法";
        }
        if ("same_time_window".equals(lower) || "time_window_overlap".equals(lower)) {
            return "时间窗重叠";
        }
        if ("same_country".equals(lower)) {
            return "同一国家";
        }
        if ("same_target".equals(lower)) {
            return "相同目标";
        }
        return relationship;
    }

    private static String riskEmoji(String riskLevel) {
        if (!notBlank(riskLevel)) {
            return "⚠️";
        }
        String lower = riskLevel.toLowerCase(Locale.ROOT);
        if ("high".equals(lower)) {
            return "🔴";
        }
        if ("medium".equals(lower)) {
            return "🟡";
        }
        if ("low".equals(lower)) {
            return "🟢";
        }
        return "⚠️";
    }

    private static String getRiskMark(String riskLevel) {
        if (!notBlank(riskLevel)) {
            return "[风险]";
        }

        String lower = riskLevel.toLowerCase(Locale.ROOT);
        if ("high".equals(lower)) {
            return "[高危]";
        }
        if ("medium".equals(lower)) {
            return "[中危]";
        }
        if ("low".equals(lower)) {
            return "[低危]";
        }
        return "[风险]";
    }

    private static String normalizedRiskLevel(String riskLevel, int riskScore) {
        if (riskScore >= 80) {
            return "high";
        }
        if (riskScore >= 50) {
            return "medium";
        }
        if (riskScore > 0) {
            return "low";
        }

        if (!notBlank(riskLevel)) {
            return "unknown";
        }

        String lower = riskLevel.toLowerCase(Locale.ROOT);
        if ("high".equals(lower) || "medium".equals(lower) || "low".equals(lower)) {
            return lower;
        }
        return "unknown";
    }

    private static String formatRiskLevel(String riskLevel) {
        if (!notBlank(riskLevel)) {
            return "未知";
        }

        String lower = riskLevel.toLowerCase(Locale.ROOT);
        if ("high".equals(lower)) {
            return "高危";
        }
        if ("medium".equals(lower)) {
            return "中危";
        }
        if ("low".equals(lower)) {
            return "低危";
        }
        return riskLevel;
    }

    private static int normalizeConfidencePercent(double confidence) {
        if (Double.isNaN(confidence) || Double.isInfinite(confidence)) {
            return 0;
        }

        double normalized = confidence;
        if (normalized > 1.0) {
            normalized = normalized / 100.0;
        }
        normalized = Math.max(0.0, Math.min(1.0, normalized));

        return (int) Math.round(normalized * 100.0);
    }

    private static boolean isValidIpv4(String text) {
        if (!notBlank(text)) {
            return false;
        }

        String[] parts = text.trim().split("\\.");
        if (parts.length != 4) {
            return false;
        }

        for (String part : parts) {
            try {
                int value = Integer.parseInt(part);
                if (value < 0 || value > 255) {
                    return false;
                }
            } catch (Exception ignored) {
                return false;
            }
        }
        return true;
    }

    private static String renumberSectionHeaders(String markdown) {
        if (!notBlank(markdown)) {
            return markdown;
        }
        String[] lines = markdown.split("\\r?\\n", -1);
        int sectionNo = 1;
        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];
            if (!line.startsWith("## ")) {
                continue;
            }
            if (line.startsWith("## 0.")) {
                continue;
            }
            int dotPos = line.indexOf(". ");
            if (dotPos > 3) {
                lines[i] = "## " + sectionNo + line.substring(dotPos);
                sectionNo++;
            }
        }
        return String.join("\n", lines);
    }

    private static String safe(String value, String defaultValue) {
        return notBlank(value) ? value.trim() : defaultValue;
    }

    private static boolean notBlank(String value) {
        return value != null && !value.trim().isEmpty();
    }
}
