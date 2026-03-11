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
 * 企业微信通知服务。
 */
public class WeComNotifier {

    private static final Logger log = LoggerFactory.getLogger(WeComNotifier.class);
    private final WeComClient weComClient;

    public WeComNotifier(WeComClient weComClient) {
        this.weComClient = weComClient;
        log.info("WeComNotifier initialized, enabled: {}", weComClient.isEnabled());
    }

    public void notifyAnalysisComplete(AnalysisReport report) {
        log.info("notifyAnalysisComplete called, enabled: {}", weComClient.isEnabled());
        
        if (!weComClient.isEnabled()) {
            log.warn("WeCom notification disabled, skipping");
            return;
        }
        if (report == null) {
            log.warn("Report is null, skipping");
            return;
        }

        try {
            String content = buildMarkdownContent(report);
            log.info("Sending markdown message to WeCom, content length: {}", content.length());
            log.debug("Markdown content preview: {}", content.substring(0, Math.min(200, content.length())));
            
            boolean success = weComClient.sendMarkdownMessage(content);
            if (success) {
                log.info("Analysis report notification sent to WeCom: {}", report.getReportId());
            } else {
                log.warn("Failed to send analysis report notification to WeCom: {}", report.getReportId());
            }
        } catch (Exception e) {
            log.error("Error sending analysis report notification to WeCom: {}", e.getMessage(), e);
        }
    }

    private String buildMarkdownContent(AnalysisReport report) {
        StringBuilder content = new StringBuilder();
        String riskMark = getRiskMark(report.getRiskLevel());
        String status = "success".equals(report.getStatus()) ? "分析完成" : 
                       ("degraded".equals(report.getStatus()) ? "降级分析" : "分析异常");

        content.append("# ").append(riskMark).append(" 安全分析报告\n\n");

        content.append("> **状态**: ").append(status).append("\n");
        content.append("> **报告ID**: `").append(report.getReportId()).append("`\n");
        content.append("> **分析时间**: ").append(formatTime(report.getAnalysisTime())).append("\n\n");

        content.append("## 分析概览\n\n");
        content.append("| 指标 | 数值 |\n");
        content.append("| --- | --- |\n");
        content.append("| 告警数量 | ").append(report.getAlertCount()).append(" |\n");
        content.append("| 风险等级 | ").append(formatRiskLevel(report.getRiskLevel())).append(" |\n");
        if (report.getRiskScore() > 0) {
            content.append("| 风险评分 | ").append(report.getRiskScore()).append("/100 |\n");
        }
        if (report.getIpIntelligenceCount() > 0) {
            content.append("| IP情报数 | ").append(report.getIpIntelligenceCount()).append(" |\n");
        }
        content.append("\n");

        if (notBlank(report.getSummary())) {
            content.append("## 执行摘要\n\n");
            content.append(report.getSummary()).append("\n\n");
        }

        if (report.getRecommendations() != null && !report.getRecommendations().isEmpty()) {
            content.append("## 防御建议\n\n");
            List<String> recommendations = uniqueFirstN(report.getRecommendations(), 5);
            for (int i = 0; i < recommendations.size(); i++) {
                content.append("**").append(i + 1).append(".** ").append(recommendations.get(i)).append("\n");
            }
            content.append("\n");
        }

        if (report.getKeyIndicators() != null && !report.getKeyIndicators().isEmpty()) {
            content.append("## 关键指标\n\n");
            int limit = Math.min(6, report.getKeyIndicators().size());
            for (int i = 0; i < limit; i++) {
                content.append("- ").append(report.getKeyIndicators().get(i)).append("\n");
            }
            content.append('\n');
        }

        if (notBlank(report.getAttackerSkillLevel()) || notBlank(report.getAutomationType()) || notBlank(report.getAttackerIntent())) {
            content.append("## 攻击活动画像\n\n");
            if (notBlank(report.getAttackerSkillLevel())) {
                content.append("- **活动复杂度**: ").append(formatSkillLevel(report.getAttackerSkillLevel())).append("\n");
            }
            if (notBlank(report.getAutomationType())) {
                content.append("- **自动化程度**: ").append(formatAutomation(report.getAutomationType())).append("\n");
            }
            if (notBlank(report.getAttackerIntent())) {
                content.append("- **主要行为意图**: ").append(formatIntent(report.getAttackerIntent())).append("\n");
            }
            content.append('\n');
        }

        if ("error".equals(report.getStatus()) && notBlank(report.getErrorMessage())) {
            content.append("## 错误信息\n\n");
            content.append("> ").append(report.getErrorMessage()).append("\n\n");
        } else if ("degraded".equals(report.getStatus()) && notBlank(report.getErrorMessage())) {
            content.append("## 降级原因\n\n");
            content.append("> ").append(report.getErrorMessage()).append("\n\n");
        }

        content.append("---\n\n");
        content.append("<font color=\"comment\">由 Input Security Starter 自动生成</font>");
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
                return "<font color=\"warning\">高危</font>";
            case "medium":
                return "<font color=\"warning\">中危</font>";
            case "low":
                return "<font color=\"info\">低危</font>";
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
        if (!weComClient.isEnabled()) {
            log.warn("WeCom notification not enabled");
            return false;
        }
        return weComClient.testConnection();
    }

    public boolean isEnabled() {
        return weComClient.isEnabled();
    }
}
