package org.example.input_security_starter.notification;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashSet;
import java.util.List;

/**
 * 飞书通知服务。
 */
public class FeishuNotifier {

    private static final Logger log = LoggerFactory.getLogger(FeishuNotifier.class);
    private final FeishuClient feishuClient;

    public FeishuNotifier(FeishuClient feishuClient) {
        this.feishuClient = feishuClient;
        log.info("FeishuNotifier initialized, enabled: {}", feishuClient.isEnabled());
    }

    public void notifyAnalysisComplete(AnalysisReport report) {
        if (!feishuClient.isEnabled()) {
            log.debug("Feishu notification disabled, skipping");
            return;
        }
        if (report == null) {
            log.warn("Report is null, skipping");
            return;
        }

        try {
            String title = buildTitle(report);
            String content = buildCardContent(report);
            boolean success = feishuClient.sendCardMessage(title, content);
            if (success) {
                log.info("Analysis report notification sent: {}", report.getReportId());
            } else {
                log.warn("Failed to send analysis report notification: {}", report.getReportId());
            }
        } catch (Exception e) {
            log.error("Error sending analysis report notification: {}", e.getMessage(), e);
        }
    }

    private String buildTitle(AnalysisReport report) {
        String riskMark = getRiskMark(report.getRiskLevel());
        String status = "success".equals(report.getStatus()) ? "分析完成" : ("degraded".equals(report.getStatus()) ? "降级分析" : "分析异常");
        return String.format("%s 安全分析报告 - %s", riskMark, status);
    }

    private String buildCardContent(AnalysisReport report) {
        StringBuilder content = new StringBuilder();
        content.append("## 分析概览\n\n");
        content.append(String.format("**报告ID**: `%s`\n", report.getReportId()));
        content.append(String.format("**分析时间**: %s\n", formatTime(report.getAnalysisTime())));
        content.append(String.format("**告警数量**: %d\n", report.getAlertCount()));
        content.append(String.format("**风险等级**: %s\n", formatRiskLevel(report.getRiskLevel())));
        if (report.getRiskScore() > 0) {
            content.append(String.format("**风险评分**: %d/100\n", report.getRiskScore()));
        }
        if (report.getIpIntelligenceCount() > 0) {
            content.append(String.format("**IP情报数**: %d\n", report.getIpIntelligenceCount()));
        }
        content.append("\n---\n\n");

        if (notBlank(report.getSummary())) {
            content.append("## 执行摘要\n\n");
            content.append(report.getSummary()).append("\n\n");
        }

        if (report.getRecommendations() != null && !report.getRecommendations().isEmpty()) {
            content.append("## 防御建议\n\n");
            List<String> recommendations = uniqueFirstN(report.getRecommendations(), 5);
            for (int i = 0; i < recommendations.size(); i++) {
                content.append(String.format("%d. %s\n", i + 1, recommendations.get(i)));
            }
            content.append("\n");
        }

        if (report.getKeyIndicators() != null && !report.getKeyIndicators().isEmpty()) {
            content.append("## 关键指标\n\n");
            int limit = Math.min(8, report.getKeyIndicators().size());
            for (int i = 0; i < limit; i++) {
                content.append("- ").append(report.getKeyIndicators().get(i)).append('\n');
            }
            content.append('\n');
        }

        if (notBlank(report.getAttackerSkillLevel()) || notBlank(report.getAutomationType()) || notBlank(report.getAttackerIntent())) {
            content.append("## 攻击活动画像\n\n");
            if (notBlank(report.getAttackerSkillLevel())) {
                content.append(String.format("**活动复杂度**: %s\n", formatSkillLevel(report.getAttackerSkillLevel())));
            }
            if (notBlank(report.getAutomationType())) {
                content.append(String.format("**自动化程度**: %s\n", formatAutomation(report.getAutomationType())));
            }
            if (notBlank(report.getAttackerIntent())) {
                content.append(String.format("**主要行为意图**: %s\n", formatIntent(report.getAttackerIntent())));
            }
            content.append('\n');
        }

        if ("error".equals(report.getStatus()) && notBlank(report.getErrorMessage())) {
            content.append("## 错误信息\n\n");
            content.append("```\n").append(report.getErrorMessage()).append("\n```\n");
        } else if ("degraded".equals(report.getStatus()) && notBlank(report.getErrorMessage())) {
            content.append("## 降级原因\n\n");
            content.append("- ").append(report.getErrorMessage()).append("\n\n");
        }

        content.append("\n---\n\n");
        content.append("_由 Input Security Starter 自动生成_");
        return content.toString();
    }

    private List<String> uniqueFirstN(List<String> source, int limit) {
        LinkedHashSet<String> dedup = new LinkedHashSet<String>();
        for (String item : source) {
            if (!notBlank(item)) {
                continue;
            }
            dedup.add(item.trim().replaceAll("\\s+", " "));
            if (dedup.size() >= limit) {
                break;
            }
        }
        return new ArrayList<String>(dedup);
    }

    private boolean notBlank(String text) {
        return text != null && !text.trim().isEmpty();
    }

    private String getRiskMark(String riskLevel) {
        if (riskLevel == null) {
            return "⚪";
        }
        switch (riskLevel.toLowerCase()) {
            case "high":
                return "🔴";
            case "medium":
                return "🟠";
            case "low":
                return "🟢";
            default:
                return "⚪";
        }
    }

    private String formatRiskLevel(String riskLevel) {
        if (riskLevel == null) {
            return "未知";
        }
        switch (riskLevel.toLowerCase()) {
            case "high":
                return "高危";
            case "medium":
                return "中危";
            case "low":
                return "低危";
            default:
                return riskLevel;
        }
    }

    private String formatSkillLevel(String skillLevel) {
        if (skillLevel == null) {
            return "未知";
        }
        switch (skillLevel.toLowerCase()) {
            case "advanced":
                return "高级";
            case "intermediate":
                return "中级";
            case "novice":
                return "初级";
            default:
                return skillLevel;
        }
    }

    private String formatAutomation(String automation) {
        if (automation == null) {
            return "未知";
        }
        switch (automation.toLowerCase()) {
            case "fully_auto":
                return "完全自动化";
            case "semi_auto":
                return "半自动化";
            case "manual":
                return "手动";
            default:
                return automation;
        }
    }

    private String formatIntent(String intent) {
        if (intent == null) {
            return "未知";
        }
        switch (intent.toLowerCase()) {
            case "reconnaissance":
                return "侦察探测";
            case "exploitation":
                return "漏洞利用";
            case "persistence":
                return "持久化控制";
            case "exfiltration":
                return "数据窃取";
            default:
                return intent;
        }
    }

    private String formatTime(Date date) {
        if (date == null) {
            return "未知";
        }
        return new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(date);
    }

    public boolean testNotification() {
        if (!feishuClient.isEnabled()) {
            log.warn("Feishu notification not enabled");
            return false;
        }
        return feishuClient.testConnection();
    }

    public boolean isEnabled() {
        return feishuClient.isEnabled();
    }
}
