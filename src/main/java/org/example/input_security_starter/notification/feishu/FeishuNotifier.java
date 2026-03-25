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
            String title = ReportMarkdownBuilder.buildTitle(report);
            String content = ReportMarkdownBuilder.buildStructuredMarkdown(report);
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
