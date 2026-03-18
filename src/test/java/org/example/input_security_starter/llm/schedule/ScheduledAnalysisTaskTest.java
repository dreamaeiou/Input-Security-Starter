package org.example.input_security_starter.llm.schedule;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.notification.feishu.FeishuClient;
import org.example.input_security_starter.notification.feishu.FeishuNotifier;
import org.junit.jupiter.api.Test;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScheduledAnalysisTaskTest {

    @Test
    void shouldSendFeishuWhenCronTriggerRuns() throws Exception {
        File alertLog = File.createTempFile("scheduled-cron", ".log");
        try {
            writeAlertLine(alertLog, "{\"client_ip\":\"1.2.3.4\",\"events\":[],\"ts\":1}");
            AlertCounter alertCounter = new AlertCounter(alertLog.getAbsolutePath(), 5);
            RecordingLlmAnalysisService llmService = new RecordingLlmAnalysisService();
            RecordingFeishuNotifier notifier = new RecordingFeishuNotifier(true);

            ScheduledAnalysisTask task = new ScheduledAnalysisTask(
                llmService,
                alertCounter,
                true,
                24L * 60L * 60L * 1000L,
                "0 0 2 * * ?",
                notifier
            );

            task.scheduledCronAnalysis();

            assertEquals(1, llmService.callCount);
            assertFalse(llmService.lastNotifyFeishu);
            assertEquals(1, notifier.notifyCount);
            assertTrue(alertCounter.getLastAnalysisTime() > 0);
            assertEquals(0, alertCounter.getUnprocessedCount());
        } finally {
            alertLog.delete();
            new File(alertLog.getAbsolutePath() + ".state.json").delete();
        }
    }

    @Test
    void shouldSendFeishuWhenAlertCountExceedsThreshold() throws Exception {
        File alertLog = File.createTempFile("scheduled-threshold", ".log");
        try {
            writeAlertLine(alertLog, "{\"client_ip\":\"1.2.3.4\",\"events\":[],\"ts\":1}");
            writeAlertLine(alertLog, "{\"client_ip\":\"5.6.7.8\",\"events\":[],\"ts\":2}");
            AlertCounter alertCounter = new AlertCounter(alertLog.getAbsolutePath(), 2);
            alertCounter.onNewAlert();
            alertCounter.onNewAlert();

            RecordingLlmAnalysisService llmService = new RecordingLlmAnalysisService();
            RecordingFeishuNotifier notifier = new RecordingFeishuNotifier(true);

            ScheduledAnalysisTask task = new ScheduledAnalysisTask(
                llmService,
                alertCounter,
                true,
                24L * 60L * 60L * 1000L,
                "0 0 2 * * ?",
                notifier
            );

            task.scheduledCountCheck();

            assertEquals(1, llmService.callCount);
            assertFalse(llmService.lastNotifyFeishu);
            assertEquals(1, notifier.notifyCount);
            assertEquals(0, alertCounter.getUnprocessedCount());
            assertTrue(alertCounter.getLastAnalysisTime() > 0);
        } finally {
            alertLog.delete();
            new File(alertLog.getAbsolutePath() + ".state.json").delete();
        }
    }

    @Test
    void shouldSkipWhenNoNewAlertsExist() throws Exception {
        File alertLog = File.createTempFile("scheduled-skip", ".log");
        try {
            writeAlertLine(alertLog, "{\"client_ip\":\"1.2.3.4\",\"events\":[],\"ts\":1}");
            AlertCounter alertCounter = new AlertCounter(alertLog.getAbsolutePath(), 1);
            alertCounter.markAnalysisCompleted(alertCounter.getTotalAlertCount(), "rpt-old");

            RecordingLlmAnalysisService llmService = new RecordingLlmAnalysisService();
            RecordingFeishuNotifier notifier = new RecordingFeishuNotifier(true);

            ScheduledAnalysisTask task = new ScheduledAnalysisTask(
                llmService,
                alertCounter,
                true,
                24L * 60L * 60L * 1000L,
                "0 0 2 * * ?",
                notifier
            );

            task.scheduledCronAnalysis();

            assertEquals(0, llmService.callCount);
            assertEquals(0, notifier.notifyCount);
        } finally {
            alertLog.delete();
            new File(alertLog.getAbsolutePath() + ".state.json").delete();
        }
    }

    private void writeAlertLine(File file, String line) throws Exception {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file, true))) {
            writer.write(line);
            writer.newLine();
        }
    }

    private static class RecordingLlmAnalysisService extends LlmAnalysisService {
        private int callCount;
        private boolean lastNotifyFeishu;

        RecordingLlmAnalysisService() {
            super(null, null, null, "unused.log", 50, 2000, 10, 5, 5000, null);
        }

        @Override
        public IncrementalAnalysisResult analyzeAttackChainAlertsIncremental(long lastProcessedLine, boolean notifyFeishu) {
            callCount++;
            lastNotifyFeishu = notifyFeishu;

            AnalysisReport report = new AnalysisReport();
            report.setReportId("rpt-test");
            report.setStatus("success");
            report.setRiskLevel("high");
            report.setRiskScore(88);
            report.setAlertCount(3);
            report.setSummary("scheduled analysis completed");
            report.setRecommendations(Collections.singletonList("block attacker"));
            return IncrementalAnalysisResult.withReport(report, lastProcessedLine + 3, 3);
        }
    }

    private static class RecordingFeishuNotifier extends FeishuNotifier {
        private int notifyCount;

        RecordingFeishuNotifier(boolean enabled) {
            super(new FakeFeishuClient(enabled));
        }

        @Override
        public void notifyAnalysisComplete(AnalysisReport report) {
            notifyCount++;
        }
    }

    private static class FakeFeishuClient extends FeishuClient {
        private final boolean enabled;

        FakeFeishuClient(boolean enabled) {
            super("", enabled);
            this.enabled = enabled;
        }

        @Override
        public boolean isEnabled() {
            return enabled;
        }
    }
}
