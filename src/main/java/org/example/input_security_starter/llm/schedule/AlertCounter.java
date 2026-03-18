package org.example.input_security_starter.llm.schedule;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

public class AlertCounter {

    private static final Logger log = LoggerFactory.getLogger(AlertCounter.class);

    private final String alertLogPath;
    private final int alertThreshold;
    private final AlertProcessingStateStore stateStore;
    private final AtomicInteger unprocessedCount = new AtomicInteger(0);
    private final AtomicLong lastProcessedLine = new AtomicLong(0);
    private final AtomicLong lastAnalysisTime = new AtomicLong(0);

    public AlertCounter(String alertLogPath, int alertThreshold) {
        this.alertLogPath = alertLogPath;
        this.alertThreshold = alertThreshold;
        this.stateStore = new AlertProcessingStateStore(alertLogPath);
        initializeCounter();
    }

    private void initializeCounter() {
        try {
            AlertProcessingState state = stateStore.load();
            lastProcessedLine.set(Math.max(0L, state.getLastProcessedLine()));
            lastAnalysisTime.set(Math.max(0L, state.getLastProcessedAt()));

            Path path = Paths.get(alertLogPath);
            if (Files.exists(path)) {
                long lineCount = Files.lines(path).count();
                if (lineCount < lastProcessedLine.get()) {
                    log.warn("Alert log appears truncated, resetting processed line pointer from {} to 0",
                        lastProcessedLine.get());
                    lastProcessedLine.set(0);
                }
                int pending = (int) Math.max(0L, lineCount - lastProcessedLine.get());
                unprocessedCount.set(pending);
                log.info("AlertCounter initialized: processedLines={}, totalLines={}, pending={}, threshold={}",
                    lastProcessedLine.get(), lineCount, pending, alertThreshold);
            } else {
                log.info("AlertCounter initialized: no existing log file, threshold={}", alertThreshold);
            }
        } catch (IOException e) {
            log.error("Failed to initialize AlertCounter: {}", e.getMessage());
        }
    }

    public void onNewAlert() {
        int count = unprocessedCount.incrementAndGet();
        log.debug("New alert recorded, unprocessed count: {}", count);
    }

    public int getUnprocessedCount() {
        return unprocessedCount.get();
    }

    public int getTotalAlertCount() {
        try {
            Path path = Paths.get(alertLogPath);
            if (Files.exists(path)) {
                return (int) Files.lines(path).count();
            }
        } catch (IOException e) {
            log.error("Failed to count alerts: {}", e.getMessage());
        }
        return 0;
    }

    public boolean hasNewAlerts() {
        int total = getTotalAlertCount();
        long processed = lastProcessedLine.get();
        if (total < processed) {
            return total > 0;
        }
        return total > processed;
    }

    public long getLastProcessedLine() {
        return lastProcessedLine.get();
    }

    public boolean shouldTriggerByCount() {
        refreshUnprocessedCountFromLog();
        int currentUnprocessed = unprocessedCount.get();
        boolean shouldTrigger = currentUnprocessed >= alertThreshold;
        if (shouldTrigger) {
            log.info("Alert threshold reached: unprocessed={} >= threshold={}", currentUnprocessed, alertThreshold);
        }
        return shouldTrigger;
    }

    public boolean shouldTriggerByTime(long intervalMs) {
        long lastTime = lastAnalysisTime.get();
        if (lastTime == 0) {
            return false;
        }
        long elapsed = System.currentTimeMillis() - lastTime;
        boolean shouldTrigger = elapsed >= intervalMs;
        if (shouldTrigger) {
            log.info("Time interval reached: elapsed={}ms >= interval={}ms", elapsed, intervalMs);
        }
        return shouldTrigger;
    }

    public void markAnalysisStarted() {
        log.info("Analysis started, resetting counter");
    }

    public void markAnalysisCompleted() {
        markAnalysisCompleted(getTotalAlertCount(), null);
    }

    public void markAnalysisCompleted(long newLastProcessedLine, String reportId) {
        int processed = unprocessedCount.getAndSet(0);
        long completedAt = System.currentTimeMillis();
        lastAnalysisTime.set(completedAt);
        lastProcessedLine.set(Math.max(0L, newLastProcessedLine));

        AlertProcessingState state = new AlertProcessingState();
        state.setLastProcessedLine(lastProcessedLine.get());
        state.setLastProcessedAt(completedAt);
        state.setLastReportId(reportId);
        stateStore.save(state);

        log.info("Analysis completed: processed={} alerts, counter reset", processed);
    }

    public long getLastAnalysisTime() {
        return lastAnalysisTime.get();
    }

    public CounterStatus getStatus() {
        refreshUnprocessedCountFromLog();
        return new CounterStatus(
            unprocessedCount.get(),
            getTotalAlertCount(),
            alertThreshold,
            lastAnalysisTime.get(),
            lastProcessedLine.get()
        );
    }

    private void refreshUnprocessedCountFromLog() {
        int total = getTotalAlertCount();
        long processed = lastProcessedLine.get();

        if (total < processed) {
            log.warn("Alert log line count {} is below processed pointer {}, treating current file as new log",
                total, processed);
            processed = 0;
            lastProcessedLine.set(0);
        }

        unprocessedCount.set((int) Math.max(0L, total - processed));
    }

    public static class CounterStatus {
        private final int unprocessedCount;
        private final int totalAlertCount;
        private final int alertThreshold;
        private final long lastAnalysisTime;
        private final long lastProcessedLine;

        public CounterStatus(int unprocessedCount, int totalAlertCount, int alertThreshold,
                             long lastAnalysisTime, long lastProcessedLine) {
            this.unprocessedCount = unprocessedCount;
            this.totalAlertCount = totalAlertCount;
            this.alertThreshold = alertThreshold;
            this.lastAnalysisTime = lastAnalysisTime;
            this.lastProcessedLine = lastProcessedLine;
        }

        public int getUnprocessedCount() { return unprocessedCount; }
        public int getTotalAlertCount() { return totalAlertCount; }
        public int getAlertThreshold() { return alertThreshold; }
        public long getLastAnalysisTime() { return lastAnalysisTime; }
        public long getLastProcessedLine() { return lastProcessedLine; }
    }
}
