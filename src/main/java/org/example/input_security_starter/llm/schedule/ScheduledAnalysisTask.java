package org.example.input_security_starter.llm.schedule;

import org.example.input_security_starter.llm.analysis.AnalysisReport;
import org.example.input_security_starter.llm.analysis.LlmAnalysisService;
import org.example.input_security_starter.notification.FeishuNotifier;
import org.example.input_security_starter.notification.WeComNotifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;

import java.util.concurrent.atomic.AtomicBoolean;

public class ScheduledAnalysisTask {

    private static final Logger log = LoggerFactory.getLogger(ScheduledAnalysisTask.class);

    private final LlmAnalysisService llmAnalysisService;
    private final AlertCounter alertCounter;
    private final boolean enabled;
    private final long scheduleIntervalMs;
    private final String scheduleCron;
    private final FeishuNotifier feishuNotifier;
    private final WeComNotifier weComNotifier;

    private final AtomicBoolean analysisInProgress = new AtomicBoolean(false);

    public ScheduledAnalysisTask(LlmAnalysisService llmAnalysisService,
                                  AlertCounter alertCounter,
                                  boolean enabled,
                                  long scheduleIntervalMs) {
        this(llmAnalysisService, alertCounter, enabled, scheduleIntervalMs, null, null, null);
    }

    public ScheduledAnalysisTask(LlmAnalysisService llmAnalysisService,
                                  AlertCounter alertCounter,
                                  boolean enabled,
                                  long scheduleIntervalMs,
                                  String scheduleCron,
                                  FeishuNotifier feishuNotifier) {
        this(llmAnalysisService, alertCounter, enabled, scheduleIntervalMs, scheduleCron, feishuNotifier, null);
    }

    public ScheduledAnalysisTask(LlmAnalysisService llmAnalysisService,
                                  AlertCounter alertCounter,
                                  boolean enabled,
                                  long scheduleIntervalMs,
                                  String scheduleCron,
                                  FeishuNotifier feishuNotifier,
                                  WeComNotifier weComNotifier) {
        this.llmAnalysisService = llmAnalysisService;
        this.alertCounter = alertCounter;
        this.enabled = enabled;
        this.scheduleIntervalMs = scheduleIntervalMs;
        this.scheduleCron = scheduleCron;
        this.feishuNotifier = feishuNotifier;
        this.weComNotifier = weComNotifier;
        
        log.info("ScheduledAnalysisTask initialized: enabled={}, intervalMs={}, cron={}",
                enabled, scheduleIntervalMs, scheduleCron);
    }

    @Scheduled(fixedDelayString = "${input-security.llm.auto-analysis.count-check-interval-ms:60000}")
    public void scheduledCountCheck() {
        if (!enabled) {
            return;
        }

        if (!acquireLock()) {
            log.debug("Analysis already in progress, skipping scheduled run");
            return;
        }

        try {
            boolean triggerByCount = alertCounter.shouldTriggerByCount();

            if (triggerByCount) {
                log.info("Triggering analysis by alert count: unprocessed={}", 
                        alertCounter.getUnprocessedCount());
                triggerAnalysis();
            } else {
                log.debug("No trigger condition met: unprocessed={}, threshold={}", 
                        alertCounter.getUnprocessedCount(), 
                        alertCounter.getStatus().getAlertThreshold());
            }
        } finally {
            releaseLock();
        }
    }

    @Scheduled(cron = "${input-security.llm.auto-analysis.schedule-cron:0 0 2 * * ?}")
    public void scheduledCronAnalysis() {
        if (!enabled) {
            return;
        }

        if (!acquireLock()) {
            log.debug("Analysis already in progress, skipping cron run");
            return;
        }

        try {
            log.info("Triggering analysis by cron schedule: {}", scheduleCron);
            triggerAnalysis();
        } finally {
            releaseLock();
        }
    }

    public void forceTrigger() {
        if (!acquireLock()) {
            log.warn("Analysis already in progress, cannot force trigger");
            return;
        }

        try {
            log.info("Force triggering analysis");
            triggerAnalysis();
        } finally {
            releaseLock();
        }
    }

    private void triggerAnalysis() {
        try {
            alertCounter.markAnalysisStarted();
            
            AnalysisReport report = llmAnalysisService.analyzeAttackChainAlerts(false);
            
            if (report != null) {
                log.info("LLM analysis completed: reportId={}, riskLevel={}, riskScore={}",
                        report.getReportId(), report.getRiskLevel(), report.getRiskScore());
                sendFeishuAfterTriggeredAnalysis(report);
                alertCounter.markAnalysisCompleted();
            } else {
                log.warn("LLM analysis returned no report");
            }
        } catch (Exception e) {
            log.error("LLM analysis failed: {}", e.getMessage(), e);
        }
    }

    private boolean acquireLock() {
        return analysisInProgress.compareAndSet(false, true);
    }

    private void releaseLock() {
        analysisInProgress.set(false);
    }

    private void sendFeishuAfterTriggeredAnalysis(AnalysisReport report) {
        if (report == null) {
            return;
        }
        if (feishuNotifier != null && feishuNotifier.isEnabled()) {
            try {
                feishuNotifier.notifyAnalysisComplete(report);
            } catch (Exception e) {
                log.error("Failed to send Feishu notification after triggered analysis: {}", e.getMessage(), e);
            }
        }
        if (weComNotifier != null && weComNotifier.isEnabled()) {
            try {
                weComNotifier.notifyAnalysisComplete(report);
            } catch (Exception e) {
                log.error("Failed to send WeCom notification after triggered analysis: {}", e.getMessage(), e);
            }
        }
    }

    public boolean isAnalysisInProgress() {
        return analysisInProgress.get();
    }

    public ScheduledAnalysisStatus getStatus() {
        return new ScheduledAnalysisStatus(
            enabled,
            scheduleIntervalMs,
            scheduleCron,
            analysisInProgress.get(),
            alertCounter.getStatus()
        );
    }

    public static class ScheduledAnalysisStatus {
        private final boolean enabled;
        private final long scheduleIntervalMs;
        private final String scheduleCron;
        private final boolean analysisInProgress;
        private final AlertCounter.CounterStatus counterStatus;

        public ScheduledAnalysisStatus(boolean enabled, long scheduleIntervalMs,
                                        String scheduleCron,
                                        boolean analysisInProgress,
                                        AlertCounter.CounterStatus counterStatus) {
            this.enabled = enabled;
            this.scheduleIntervalMs = scheduleIntervalMs;
            this.scheduleCron = scheduleCron;
            this.analysisInProgress = analysisInProgress;
            this.counterStatus = counterStatus;
        }

        public boolean isEnabled() { return enabled; }
        public long getScheduleIntervalMs() { return scheduleIntervalMs; }
        public String getScheduleCron() { return scheduleCron; }
        public boolean isAnalysisInProgress() { return analysisInProgress; }
        public AlertCounter.CounterStatus getCounterStatus() { return counterStatus; }
    }
}
