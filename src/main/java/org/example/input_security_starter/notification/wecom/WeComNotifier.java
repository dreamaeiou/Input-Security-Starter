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
            String content = ReportMarkdownBuilder.buildStructuredMarkdown(report);
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
