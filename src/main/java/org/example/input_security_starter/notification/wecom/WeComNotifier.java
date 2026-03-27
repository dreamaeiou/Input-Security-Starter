package org.example.input_security_starter.notification.wecom;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.notification.ReportMarkdownBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WeComNotifier {

    private static final Logger log = LoggerFactory.getLogger(WeComNotifier.class);
    private final WeComClient weComClient;

    public WeComNotifier(WeComClient weComClient) {
        this.weComClient = weComClient;
        log.info("WeComNotifier initialized, enabled: {}", weComClient.isEnabled());
    }

    public void notifyAnalysisComplete(AnalysisReport report) {
        if (!weComClient.isEnabled()) {
            log.warn("WeCom notification disabled, skipping");
            return;
        }
        if (report == null) {
            log.warn("Report is null, skipping");
            return;
        }

        try {
            String content1 = ReportMarkdownBuilder.buildTacticalSummary(report);
            boolean firstOk = weComClient.sendMarkdownMessage(content1);

            String title2 = "\uD83D\uDCCB \u60C5\u62A5\u8BE6\u60C5 \u00B7 " + report.getReportId();
            String content2 = "## " + title2 + "\n\n" + ReportMarkdownBuilder.buildIntelligenceJsonBlock(report);
            boolean secondOk = weComClient.sendMarkdownMessage(content2);

            if (firstOk && secondOk) {
                log.info("Analysis report notifications sent to WeCom (2 messages): {}", report.getReportId());
            } else {
                log.warn("Failed to send one or more WeCom notifications: {}, firstOk={}, secondOk={}",
                    report.getReportId(), firstOk, secondOk);
            }
        } catch (Exception e) {
            log.error("Error sending analysis report notification to WeCom: {}", e.getMessage(), e);
        }
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
