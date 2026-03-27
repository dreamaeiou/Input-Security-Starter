package org.example.input_security_starter.notification.feishu;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.notification.ReportMarkdownBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
            String title1 = ReportMarkdownBuilder.buildTitle(report);
            String content1 = ReportMarkdownBuilder.buildTacticalSummary(report);
            boolean firstOk = feishuClient.sendCardMessage(title1, content1);

            String title2 = "\uD83D\uDCCB \u60C5\u62A5\u8BE6\u60C5 \u00B7 " + report.getReportId();
            String content2 = ReportMarkdownBuilder.buildIntelligenceJsonBlock(report);
            boolean secondOk = feishuClient.sendCardMessage(title2, content2);

            if (firstOk && secondOk) {
                log.info("Analysis report notifications sent (2 messages): {}", report.getReportId());
            } else {
                log.warn("Failed to send one or more Feishu notifications: {}, firstOk={}, secondOk={}",
                    report.getReportId(), firstOk, secondOk);
            }
        } catch (Exception e) {
            log.error("Error sending analysis report notification: {}", e.getMessage(), e);
        }
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
