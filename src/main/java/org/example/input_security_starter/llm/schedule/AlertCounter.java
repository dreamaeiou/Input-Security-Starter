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
    private final AtomicInteger unprocessedCount = new AtomicInteger(0);
    private final AtomicLong lastProcessedLine = new AtomicLong(0);
    private final AtomicLong lastAnalysisTime = new AtomicLong(0);

    public AlertCounter(String alertLogPath, int alertThreshold) {
        this.alertLogPath = alertLogPath;
        this.alertThreshold = alertThreshold;
        initializeCounter();
    }

    private void initializeCounter() {
        try {
            Path path = Paths.get(alertLogPath);
            if (Files.exists(path)) {
                long lineCount = Files.lines(path).count();
                lastProcessedLine.set(lineCount);
                log.info("AlertCounter initialized: processedLines={}, threshold={}", lineCount, alertThreshold);
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

    public boolean shouldTriggerByCount() {
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
        int processed = unprocessedCount.getAndSet(0);
        lastAnalysisTime.set(System.currentTimeMillis());
        
        try {
            Path path = Paths.get(alertLogPath);
            if (Files.exists(path)) {
                long lineCount = Files.lines(path).count();
                lastProcessedLine.set(lineCount);
            }
        } catch (IOException e) {
            log.error("Failed to update processed line count: {}", e.getMessage());
        }
        
        log.info("Analysis completed: processed={} alerts, counter reset", processed);
    }

    public long getLastAnalysisTime() {
        return lastAnalysisTime.get();
    }

    public CounterStatus getStatus() {
        return new CounterStatus(
            unprocessedCount.get(),
            getTotalAlertCount(),
            alertThreshold,
            lastAnalysisTime.get(),
            lastProcessedLine.get()
        );
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
