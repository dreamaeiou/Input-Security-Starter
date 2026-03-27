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
            String title1 = ReportMarkdownBuilder.buildTitle(report);
            String content1 = ReportMarkdownBuilder.buildTacticalSummary(report);
            boolean firstOk = dingTalkClient.sendMarkdownMessage(title1, content1);

            String title2 = "\uD83D\uDCCB \u60C5\u62A5\u8BE6\u60C5 \u00B7 " + report.getReportId();
            String content2 = ReportMarkdownBuilder.buildIntelligenceJsonBlock(report);
            boolean secondOk = dingTalkClient.sendMarkdownMessage(title2, content2);

            if (firstOk && secondOk) {
                log.info("Analysis report notifications sent to DingTalk (2 messages): {}", report.getReportId());
            } else {
                log.warn("Failed to send one or more DingTalk notifications: {}, firstOk={}, secondOk={}",
                    report.getReportId(), firstOk, secondOk);
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
