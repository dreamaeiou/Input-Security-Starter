package org.example.input_security_starter.notification.dingtalk;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.notification.ReportMarkdownBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DingTalkNotifier {

    private static final Logger log = LoggerFactory.getLogger(DingTalkNotifier.class);
    private final DingTalkClient dingTalkClient;

    public DingTalkNotifier(DingTalkClient dingTalkClient) {
        this.dingTalkClient = dingTalkClient;
        log.info("DingTalkNotifier initialized, enabled: {}", dingTalkClient.isEnabled());
    }

    public void notifyAnalysisComplete(AnalysisReport report) {
        if (!dingTalkClient.isEnabled()) {
            log.debug("DingTalk notification disabled, skipping");
            return;
        }
        if (report == null) {
            log.warn("Report is null, skipping");
            return;
        }

        try {
            String title = ReportMarkdownBuilder.buildTitle(report);
            String content = ReportMarkdownBuilder.buildStructuredMarkdown(report);
            boolean success = dingTalkClient.sendMarkdownMessage(title, content);
            if (success) {
                log.info("Analysis report notification sent to DingTalk: {}", report.getReportId());
            } else {
                log.warn("Failed to send analysis report notification to DingTalk: {}", report.getReportId());
            }
        } catch (Exception e) {
            log.error("Error sending analysis report notification to DingTalk: {}", e.getMessage(), e);
        }
    }

    public boolean testNotification() {
        if (!dingTalkClient.isEnabled()) {
            log.warn("DingTalk notification not enabled");
            return false;
        }
        return dingTalkClient.testConnection();
    }

    public boolean isEnabled() {
        return dingTalkClient.isEnabled();
    }
}
